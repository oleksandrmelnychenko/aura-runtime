use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::ids::{ConversationId, SenderId};
use crate::types::{
    BehavioralTrend, CircleTier, Confidence, ContactSnapshot, DetectionSignal, SignalFamily,
    ThreatType,
};

use super::events::EventKind;

use super::events::ContextEvent;

const WEEK_MS: u64 = 7 * 24 * 60 * 60 * 1000;
const DAY_MS: u64 = 24 * 60 * 60 * 1000;
const MAX_SNAPSHOTS: usize = 26;
const MAX_NARRATIVE_TIMELINE: usize = 100;
const MAX_MESSAGE_FINGERPRINTS: usize = 200;
const MAX_WEEKLY_PROPAGANDA_BUCKETS: usize = 52;
/// Default upper bound for the number of contact profiles stored.
pub const DEFAULT_MAX_CONTACT_PROFILES: usize = 1_000;

fn default_rating() -> f32 {
    50.0
}

fn default_trust() -> f32 {
    0.5
}

/// Indicates how a contact's age was determined.
///
/// The source affects confidence weighting in age-gap detection:
/// - `ParentVerified`: score used as-is (full confidence).
/// - `UserReported`: score multiplied by 0.85 (self-report may be false).
/// - `MlInferred`: score multiplied by 0.7 (ML estimate is noisy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AgeSource {
    /// Age verified by a parent or guardian (highest confidence).
    ParentVerified,
    /// Age self-reported by the contact during conversation.
    #[default]
    UserReported,
    /// Age inferred by the ML pipeline from linguistic features.
    MlInferred,
}

impl AgeSource {
    /// Returns a confidence multiplier for age-gap scoring.
    pub fn confidence_factor(self) -> f32 {
        match self {
            AgeSource::ParentVerified => 1.0,
            AgeSource::UserReported => 0.85,
            AgeSource::MlInferred => 0.7,
        }
    }
}

/// Captures aggregated behavioral statistics for a single weekly period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralSnapshot {
    pub period_start_ms: u64,
    pub period_end_ms: u64,
    pub total_messages: u32,
    pub hostile_count: u32,
    pub supportive_count: u32,
    pub neutral_count: u32,
    pub grooming_count: u32,
    pub manipulation_count: u32,
    #[serde(default)]
    pub propaganda_count: u32,
    pub avg_severity: f32,
}

/// Represents the exportable state of a behavioral snapshot.
#[derive(Debug, Clone)]
pub struct BehavioralSnapshotState {
    pub period_start_ms: u64,
    pub period_end_ms: u64,
    pub total_messages: u32,
    pub hostile_count: u32,
    pub supportive_count: u32,
    pub neutral_count: u32,
    pub grooming_count: u32,
    pub manipulation_count: u32,
    pub propaganda_count: u32,
    pub avg_severity: f32,
}

impl From<&BehavioralSnapshot> for BehavioralSnapshotState {
    fn from(snapshot: &BehavioralSnapshot) -> Self {
        Self {
            period_start_ms: snapshot.period_start_ms,
            period_end_ms: snapshot.period_end_ms,
            total_messages: snapshot.total_messages,
            hostile_count: snapshot.hostile_count,
            supportive_count: snapshot.supportive_count,
            neutral_count: snapshot.neutral_count,
            grooming_count: snapshot.grooming_count,
            manipulation_count: snapshot.manipulation_count,
            propaganda_count: snapshot.propaganda_count,
            avg_severity: snapshot.avg_severity,
        }
    }
}

impl From<BehavioralSnapshotState> for BehavioralSnapshot {
    fn from(snapshot: BehavioralSnapshotState) -> Self {
        Self {
            period_start_ms: snapshot.period_start_ms,
            period_end_ms: snapshot.period_end_ms,
            total_messages: snapshot.total_messages,
            hostile_count: snapshot.hostile_count,
            supportive_count: snapshot.supportive_count,
            neutral_count: snapshot.neutral_count,
            grooming_count: snapshot.grooming_count,
            manipulation_count: snapshot.manipulation_count,
            propaganda_count: snapshot.propaganda_count,
            avg_severity: snapshot.avg_severity,
        }
    }
}

impl BehavioralSnapshot {
    fn new(start_ms: u64) -> Self {
        Self {
            period_start_ms: start_ms,
            period_end_ms: 0,
            total_messages: 0,
            hostile_count: 0,
            supportive_count: 0,
            neutral_count: 0,
            grooming_count: 0,
            manipulation_count: 0,
            propaganda_count: 0,
            avg_severity: 0.0,
        }
    }

    /// Returns the ratio of hostile messages to total messages in this period.
    pub fn hostile_ratio(&self) -> f32 {
        if self.total_messages == 0 {
            0.0
        } else {
            self.hostile_count as f32 / self.total_messages as f32
        }
    }

    /// Returns the ratio of supportive messages to total messages in this period.
    pub fn supportive_ratio(&self) -> f32 {
        if self.total_messages == 0 {
            0.0
        } else {
            self.supportive_count as f32 / self.total_messages as f32
        }
    }
}

/// Tracks behavioral history and risk metrics for a single contact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactProfile {
    pub sender_id: SenderId,
    pub(crate) conversations: Vec<ConversationId>,
    #[serde(default)]
    weekly_snapshots: VecDeque<BehavioralSnapshot>,
    #[serde(default)]
    current_snapshot: Option<BehavioralSnapshot>,
    #[serde(default)]
    active_days: HashSet<u32>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub total_messages: u64,
    pub conversation_count: usize,
    pub grooming_event_count: u64,
    pub bullying_event_count: u64,
    pub manipulation_event_count: u64,
    #[serde(default)]
    pub propaganda_event_count: u64,
    #[serde(default)]
    pub propaganda_source_count: u64,
    #[serde(default)]
    pub narrative_hits: Vec<(u8, u32)>,
    #[serde(default)]
    pub propaganda_score: f32,
    #[serde(default)]
    pub narrative_diversity: u8,
    #[serde(default)]
    pub first_propaganda_ms: u64,
    #[serde(default)]
    pub last_propaganda_ms: u64,
    #[serde(default)]
    pub propaganda_conversations: Vec<ConversationId>,
    #[serde(default)]
    pub hourly_activity: [u16; 24],
    #[serde(default)]
    pub message_fingerprints: VecDeque<u64>,
    #[serde(default)]
    pub narrative_timeline: VecDeque<(u64, u8)>,
    #[serde(default)]
    pub weekly_propaganda_counts: VecDeque<(u64, u16)>,
    #[serde(default)]
    last_fingerprint_marker: Option<(u64, u64)>,
    severity_count: u64,
    severity_sum: f32,
    #[serde(default = "default_rating")]
    pub rating: f32,
    #[serde(default = "default_trust")]
    pub trust_level: f32,
    #[serde(default)]
    pub inferred_age: Option<u16>,
    #[serde(default)]
    pub age_source: AgeSource,
    #[serde(default)]
    pub circle_tier: CircleTier,
    #[serde(default)]
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
            age_source: AgeSource::default(),
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
        let delta = event.kind.rating_delta();
        self.rating = (self.rating + delta).clamp(0.0, 100.0);

        self.update_current_snapshot(event);

        let day_index = (event.timestamp_ms / DAY_MS) as u32;
        self.active_days.insert(day_index);

        self.recalculate_circle_tier();

        if event.kind.is_propaganda_indicator() {
            self.decay_trust(event.kind.severity() * 0.5);
        } else if event.kind.is_hostile() {
            self.decay_trust(event.kind.severity());
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
        if event.kind.is_hostile() {
            snapshot.hostile_count += 1;
        } else if event.kind.is_supportive() {
            snapshot.supportive_count += 1;
        } else {
            snapshot.neutral_count += 1;
        }
        if event.kind.is_core_grooming_indicator() {
            snapshot.grooming_count += 1;
        }
        if event.kind.is_manipulation_indicator() {
            snapshot.manipulation_count += 1;
        }
        if event.kind.is_propaganda_indicator() {
            snapshot.propaganda_count += 1;
        }

        let n = snapshot.total_messages as f32;
        snapshot.avg_severity = snapshot.avg_severity * ((n - 1.0) / n) + event.kind.severity() / n;
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

    /// Fix up fields that may be missing from older serialized state.
    fn post_deserialize_fixup(&mut self) {
        if self.is_trusted && self.trust_level < 0.7 {
            self.trust_level = 1.0;
        }
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

fn trend_severity(trend: &BehavioralTrend) -> u8 {
    match trend {
        BehavioralTrend::Stable => 0,
        BehavioralTrend::Improving => 0,
        BehavioralTrend::GradualWorsening => 1,
        BehavioralTrend::RapidWorsening => 2,
        BehavioralTrend::RoleReversal => 3,
    }
}

/// Manages a bounded collection of contact profiles and provides anomaly detection.
pub struct ContactProfiler {
    profiles: HashMap<SenderId, ContactProfile>,
    max_profiles: usize,
}

/// Represents the serializable wire state of the contact profiler.
#[derive(Debug, Clone)]
pub struct ContactProfilerWireState {
    pub profiles: Vec<ContactProfileState>,
}

impl Default for ContactProfiler {
    fn default() -> Self {
        Self::new()
    }
}

impl ContactProfiler {
    /// Creates a new profiler with the default maximum profile limit.
    pub fn new() -> Self {
        Self::with_max_profiles(DEFAULT_MAX_CONTACT_PROFILES)
    }

    /// Creates a new profiler with an explicit maximum profile count.
    pub fn with_max_profiles(max_profiles: usize) -> Self {
        Self {
            profiles: HashMap::new(),
            max_profiles: max_profiles.max(1),
        }
    }

    /// Records a context event, updating or creating the corresponding contact profile.
    pub fn record_event(&mut self, event: &ContextEvent) {
        self.ensure_capacity_for_sender(&event.sender_id);
        let profile = self
            .profiles
            .entry(event.sender_id.clone())
            .or_insert_with(|| ContactProfile::new(event.sender_id.clone(), event.timestamp_ms));

        profile.total_messages += 1;
        profile.last_seen_ms = profile.last_seen_ms.max(event.timestamp_ms);

        if !profile.conversations.contains(&event.conversation_id) {
            profile.conversations.push(event.conversation_id.clone());
            profile.conversation_count = profile.conversations.len();
        }

        if event.kind.is_core_grooming_indicator() {
            profile.grooming_event_count += 1;
        }
        if event.kind.is_bullying_indicator() {
            profile.bullying_event_count += 1;
        }
        if event.kind.is_manipulation_indicator() {
            profile.manipulation_event_count += 1;
        }

        let is_propaganda_event = event.kind.is_propaganda_indicator();
        if is_propaganda_event {
            profile.propaganda_event_count += 1;
            if profile.first_propaganda_ms == 0 {
                profile.first_propaganda_ms = event.timestamp_ms;
            }
            profile.last_propaganda_ms = event.timestamp_ms;

            if let Some(ref st) = event.subtype {
                profile.record_narrative_hit(st, event.timestamp_ms);
            }
            profile.record_weekly_propaganda_count(event.timestamp_ms);
            if let Some(content_hash) = event.content_hash {
                profile.record_message_fingerprint(event.timestamp_ms, content_hash);
            }

            let hour = ((event.timestamp_ms / 3_600_000) % 24) as usize;
            profile.hourly_activity[hour] = profile.hourly_activity[hour].saturating_add(1);

            if !profile
                .propaganda_conversations
                .contains(&event.conversation_id)
            {
                if profile.propaganda_conversations.len() < 50 {
                    profile
                        .propaganda_conversations
                        .push(event.conversation_id.clone());
                }
            }

            if event.kind == EventKind::SuspiciousSource {
                profile.propaganda_source_count += 1;
            }
        }
        if profile.propaganda_event_count > 0 {
            profile.update_propaganda_score();
        }

        let severity = event.kind.severity();
        if severity > 0.0 {
            profile.severity_sum += severity;
            profile.severity_count += 1;
        }

        profile.update_rating(event);
    }

    /// Updates the maximum profile limit and evicts excess profiles if needed.
    pub fn update_max_profiles(&mut self, max_profiles: usize) {
        self.max_profiles = max_profiles.max(1);
        self.enforce_profile_limit();
    }

    /// Returns true if the sender is unknown or was first seen within the last 48 hours.
    pub fn is_new_contact(&self, sender_id: &str) -> bool {
        match self.profiles.get(sender_id) {
            None => true,
            Some(p) => p.relationship_age_ms() < 48 * 60 * 60 * 1000,
        }
    }

    /// Returns true if the sender appears in many conversations with grooming indicators.
    pub fn contacts_many_minors(&self, sender_id: &str) -> bool {
        match self.profiles.get(sender_id) {
            None => false,
            Some(p) => p.conversation_count >= 5 && p.grooming_event_count >= 3,
        }
    }

    /// Returns the profile for the given sender, if one exists.
    pub fn profile(&self, sender_id: &str) -> Option<&ContactProfile> {
        self.profiles.get(sender_id)
    }

    /// Returns a lightweight snapshot for the given sender, if a profile exists.
    pub fn snapshot(&self, sender_id: &str) -> Option<ContactSnapshot> {
        self.profile(sender_id)
            .map(|profile| profile.snapshot(self.is_new_contact(sender_id)))
    }

    /// Returns all contact profiles sorted by risk score in descending order.
    pub fn contacts_by_risk(&self) -> Vec<&ContactProfile> {
        let mut profiles = Vec::with_capacity(self.profiles.len());
        for p in self.profiles.values() {
            profiles.push(p);
        }
        profiles.sort_by(|a, b| {
            b.risk_score()
                .partial_cmp(&a.risk_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        profiles
    }

    /// Marks the given sender as fully trusted.
    pub fn mark_trusted(&mut self, sender_id: &str) {
        if let Some(profile) = self.profiles.get_mut(sender_id) {
            profile.trust_level = 1.0;
            profile.is_trusted = true;
        }
    }

    /// Sets the inferred age for a sender if not already set and the value is valid (5-99).
    ///
    /// A higher-confidence source always overwrites a lower-confidence one
    /// (e.g. `ParentVerified` replaces `MlInferred`), but a same-or-lower
    /// source is ignored once the age is already set.
    pub fn set_inferred_age(&mut self, sender_id: &str, age: u16) {
        self.set_inferred_age_with_source(sender_id, age, AgeSource::UserReported);
    }

    /// Sets the inferred age with an explicit source confidence tag.
    pub fn set_inferred_age_with_source(
        &mut self,
        sender_id: &str,
        age: u16,
        source: AgeSource,
    ) {
        if let Some(profile) = self.profiles.get_mut(sender_id) {
            // Require at least minimal history before accepting claimed age.
            if profile.total_messages < 2 {
                return;
            }
            if !(5..=99).contains(&age) {
                return;
            }
            let dominated = match (profile.inferred_age, source, profile.age_source) {
                (None, _, _) => false,
                (Some(_), AgeSource::ParentVerified, AgeSource::ParentVerified) => true,
                (Some(_), AgeSource::ParentVerified, _) => false,
                (Some(_), _, _) => true,
            };
            if !dominated {
                profile.inferred_age = Some(age);
                profile.age_source = source;
            }
        }
    }

    /// Generates detection signals if a significant age gap exists between sender and account holder.
    pub fn check_age_gap(
        &self,
        sender_id: &str,
        account_holder_age: Option<u16>,
    ) -> Vec<DetectionSignal> {
        let mut signals = Vec::new();

        let profile = match self.profiles.get(sender_id) {
            Some(p) => p,
            None => return signals,
        };

        if profile.is_trusted {
            return signals;
        }

        let sender_age = match profile.inferred_age {
            Some(age) => age,
            None => return signals,
        };

        let holder_age = match account_holder_age {
            Some(age) => age,
            None => return signals,
        };

        if holder_age < 18 && sender_age >= 18 {
            let gap = sender_age - holder_age;
            if gap >= 5 {
                let raw_score = if profile.grooming_event_count > 0 {
                    (0.6 + gap as f32 * 0.02).min(0.95)
                } else {
                    (0.3 + gap as f32 * 0.01).min(0.6)
                };
                // Scale the score by how confident we are in the age
                // data. ParentVerified → full score, MlInferred → 70%.
                let score = (raw_score * profile.age_source.confidence_factor()).min(0.95);

                signals.push(DetectionSignal::context(
                    ThreatType::Grooming,
                    score,
                    Confidence::Medium,
                    SignalFamily::Conversation,
                    if profile.grooming_event_count > 0 {
                        "conversation.contact.age_gap_with_grooming"
                    } else {
                        "conversation.contact.age_gap"
                    },
                    format!(
                        "Age gap detected: sender claims age {sender_age}, account holder is {holder_age} (gap: {gap} years){}",
                        if profile.grooming_event_count > 0 {
                            format!(" with {} grooming indicators", profile.grooming_event_count)
                        } else {
                            String::new()
                        }
                    ),
                ));
            }
        }

        signals
    }

    /// Checks a contact for anomalous patterns such as new risky contacts or multi-conversation predators.
    pub fn check_anomalies(&self, sender_id: &str, is_minor_account: bool) -> Vec<DetectionSignal> {
        let mut signals = Vec::new();

        let profile = match self.profiles.get(sender_id) {
            Some(p) => p,
            None => return signals,
        };

        if profile.is_trusted {
            return signals;
        }

        let risk = profile.risk_score();

        if is_minor_account && self.is_new_contact(sender_id) && risk >= 0.3 {
            let dominant_threat = profile.dominant_contact_risk_threat();
            signals.push(DetectionSignal::context(
                dominant_threat,
                risk,
                Confidence::Medium,
                SignalFamily::Conversation,
                "conversation.contact.new_risky_contact",
                format!(
                    "New contact with suspicious behavior pattern (risk: {risk:.2}). {} grooming indicators, {} manipulation indicators, {} bullying indicators.",
                    profile.grooming_event_count,
                    profile.manipulation_event_count,
                    profile.bullying_event_count,
                ),
            ));
        }

        if is_minor_account && profile.conversation_count >= 5 && profile.grooming_event_count >= 3 {
            signals.push(DetectionSignal::context(
                ThreatType::Grooming,
                0.8,
                Confidence::High,
                SignalFamily::Conversation,
                "conversation.contact.multi_conversation_predator_pattern",
                format!(
                    "Contact appears in {} conversations with {} grooming indicators — possible predator pattern",
                    profile.conversation_count,
                    profile.grooming_event_count,
                ),
            ));
        }

        signals
    }

    /// Generates signals for behavioral trend changes such as rapid worsening or role reversal.
    pub fn check_behavioral_shift(&self, sender_id: &str) -> Vec<DetectionSignal> {
        let mut signals = Vec::new();
        let profile = match self.profiles.get(sender_id) {
            Some(p) => p,
            None => return signals,
        };

        if profile.weekly_snapshots.len() < 3 {
            return signals;
        }

        match profile.trend {
            BehavioralTrend::RapidWorsening => {
                let mut score = 0.5;
                if profile.circle_tier == CircleTier::Inner {
                    score += 0.1;
                }
                signals.push(DetectionSignal::context(
                    ThreatType::Manipulation,
                    score,
                    Confidence::Medium,
                    SignalFamily::Conversation,
                    "conversation.contact.behavior_rapid_worsening",
                    format!(
                        "Contact {} showing rapid behavioral worsening (rating: {:.0})",
                        sender_id, profile.rating
                    ),
                ));
            }
            BehavioralTrend::RoleReversal => {
                let mut score = 0.6;
                if profile.circle_tier == CircleTier::Inner {
                    score += 0.1;
                }
                if profile.trust_level < 0.4 {
                    if let Some(first) = profile.weekly_snapshots.front() {
                        if first.supportive_ratio() > 0.3 {
                            score += 0.1;
                        }
                    }
                }
                signals.push(DetectionSignal::context(
                    ThreatType::Bullying,
                    score,
                    Confidence::High,
                    SignalFamily::Conversation,
                    "conversation.contact.behavior_role_reversal",
                    format!(
                        "Contact {} role reversal: was supportive, now hostile (rating: {:.0})",
                        sender_id, profile.rating
                    ),
                ));
            }
            BehavioralTrend::GradualWorsening => {
                let mut score = 0.35;
                if profile.circle_tier == CircleTier::Inner {
                    score += 0.1;
                }
                signals.push(DetectionSignal::context(
                    ThreatType::Manipulation,
                    score,
                    Confidence::Medium,
                    SignalFamily::Conversation,
                    "conversation.contact.behavior_gradual_worsening",
                    format!(
                        "Contact {} showing gradual behavioral worsening over weeks (rating: {:.0})",
                        sender_id, profile.rating
                    ),
                ));
            }
            BehavioralTrend::Stable | BehavioralTrend::Improving => {}
        }

        if profile.rating < 20.0 && profile.circle_tier == CircleTier::Inner {
            signals.push(DetectionSignal::context(
                ThreatType::Bullying,
                0.55,
                Confidence::High,
                SignalFamily::Conversation,
                "conversation.contact.inner_circle_low_rating",
                format!(
                    "Inner circle contact {} has critically low rating ({:.0}/100)",
                    sender_id, profile.rating
                ),
            ));
        }

        signals
    }

    /// Exports all profiles as a cloneable state snapshot.
    pub fn export(&self) -> ContactProfilerState {
        let mut profiles = Vec::with_capacity(self.profiles.len());
        for p in self.profiles.values() {
            profiles.push(p.clone());
        }
        ContactProfilerState { profiles }
    }

    /// Exports all profiles as a wire-format state for serialization.
    pub fn export_wire_state(&self) -> ContactProfilerWireState {
        let mut profiles = Vec::with_capacity(self.profiles.len());
        for p in self.profiles.values() {
            profiles.push(ContactProfileState::from(p));
        }
        ContactProfilerWireState { profiles }
    }

    /// Imports profiles from a state snapshot, replacing existing profiles with the same sender ID.
    pub fn import(&mut self, state: ContactProfilerState) {
        for mut profile in state.profiles {
            profile.post_deserialize_fixup();
            self.profiles.insert(profile.sender_id.clone(), profile);
        }
        self.enforce_profile_limit();
    }

    /// Merge-based import: preserves local profiles, takes the most cautious values.
    pub fn merge_import(&mut self, state: ContactProfilerState) {
        for mut incoming in state.profiles {
            incoming.post_deserialize_fixup();
            match self.profiles.get_mut(&incoming.sender_id) {
                Some(local) => {
                    let incoming_average = incoming.average_severity();
                    let incoming_severity_count = incoming.severity_count;
                    local.first_seen_ms = local.first_seen_ms.min(incoming.first_seen_ms);
                    local.last_seen_ms = local.last_seen_ms.max(incoming.last_seen_ms);
                    local.total_messages = local.total_messages.max(incoming.total_messages);
                    local.grooming_event_count = local
                        .grooming_event_count
                        .max(incoming.grooming_event_count);
                    local.bullying_event_count = local
                        .bullying_event_count
                        .max(incoming.bullying_event_count);
                    local.manipulation_event_count = local
                        .manipulation_event_count
                        .max(incoming.manipulation_event_count);
                    local.propaganda_event_count = local
                        .propaganda_event_count
                        .max(incoming.propaganda_event_count);
                    local.propaganda_source_count = local
                        .propaganda_source_count
                        .max(incoming.propaganda_source_count);
                    local.first_propaganda_ms = if local.first_propaganda_ms == 0 {
                        incoming.first_propaganda_ms
                    } else if incoming.first_propaganda_ms == 0 {
                        local.first_propaganda_ms
                    } else {
                        local.first_propaganda_ms.min(incoming.first_propaganda_ms)
                    };
                    local.last_propaganda_ms =
                        local.last_propaganda_ms.max(incoming.last_propaganda_ms);
                    local.propaganda_score = local.propaganda_score.max(incoming.propaganda_score);
                    local.narrative_diversity =
                        local.narrative_diversity.max(incoming.narrative_diversity);
                    for (nid, count) in &incoming.narrative_hits {
                        let mut found = false;
                        for entry in &mut local.narrative_hits {
                            if entry.0 == *nid {
                                entry.1 = entry.1.max(*count);
                                found = true;
                                break;
                            }
                        }
                        if !found && local.narrative_hits.len() < 15 {
                            local.narrative_hits.push((*nid, *count));
                        }
                    }
                    local.narrative_diversity = local.narrative_hits.len() as u8;
                    let mut known_propaganda_conversations: HashSet<ConversationId> =
                        HashSet::with_capacity(local.propaganda_conversations.len());
                    for conv in &local.propaganda_conversations {
                        known_propaganda_conversations.insert(conv.clone());
                    }
                    for conv in &incoming.propaganda_conversations {
                        if local.propaganda_conversations.len() >= 50 {
                            break;
                        }
                        if known_propaganda_conversations.insert(conv.clone()) {
                            local.propaganda_conversations.push(conv.clone());
                        }
                    }
                    for (idx, count) in incoming.hourly_activity.iter().enumerate() {
                        local.hourly_activity[idx] = local.hourly_activity[idx].max(*count);
                    }

                    let mut local_fingerprint_counts: HashMap<u64, usize> = HashMap::new();
                    for fingerprint in &local.message_fingerprints {
                        let entry = local_fingerprint_counts.entry(*fingerprint).or_insert(0);
                        *entry += 1;
                    }
                    let mut incoming_fingerprint_counts: HashMap<u64, usize> = HashMap::new();
                    for fingerprint in incoming.message_fingerprints {
                        let entry = incoming_fingerprint_counts.entry(fingerprint).or_insert(0);
                        *entry += 1;
                    }
                    let mut fingerprint_counts = local_fingerprint_counts;
                    for (fingerprint, incoming_count) in incoming_fingerprint_counts {
                        let entry = fingerprint_counts.entry(fingerprint).or_insert(0);
                        *entry = (*entry).max(incoming_count);
                    }
                    let mut ranked_fingerprints: Vec<(u64, usize)> =
                        Vec::with_capacity(fingerprint_counts.len());
                    for (fingerprint, count) in fingerprint_counts {
                        ranked_fingerprints.push((fingerprint, count));
                    }
                    ranked_fingerprints
                        .sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                    local.message_fingerprints.clear();
                    'outer: for (fingerprint, count) in ranked_fingerprints {
                        for _ in 0..count {
                            if local.message_fingerprints.len() >= MAX_MESSAGE_FINGERPRINTS {
                                break 'outer;
                            }
                            local.message_fingerprints.push_back(fingerprint);
                        }
                    }
                    local.last_fingerprint_marker = None;

                    let mut merged_timeline = Vec::with_capacity(
                        local.narrative_timeline.len() + incoming.narrative_timeline.len(),
                    );
                    for point in &local.narrative_timeline {
                        merged_timeline.push(*point);
                    }
                    for point in incoming.narrative_timeline {
                        merged_timeline.push(point);
                    }
                    merged_timeline
                        .sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
                    merged_timeline.dedup();
                    if merged_timeline.len() > MAX_NARRATIVE_TIMELINE {
                        let overflow = merged_timeline.len() - MAX_NARRATIVE_TIMELINE;
                        merged_timeline.drain(0..overflow);
                    }
                    local.narrative_timeline.clear();
                    for point in merged_timeline {
                        local.narrative_timeline.push_back(point);
                    }

                    for (week_start_ms, count) in incoming.weekly_propaganda_counts {
                        let mut found = false;
                        for entry in &mut local.weekly_propaganda_counts {
                            if entry.0 == week_start_ms {
                                entry.1 = entry.1.max(count);
                                found = true;
                                break;
                            }
                        }
                        if !found {
                            local
                                .weekly_propaganda_counts
                                .push_back((week_start_ms, count));
                        }
                    }
                    let mut merged_weekly =
                        Vec::with_capacity(local.weekly_propaganda_counts.len());
                    for entry in &local.weekly_propaganda_counts {
                        merged_weekly.push(*entry);
                    }
                    merged_weekly.sort_unstable_by(|a, b| a.0.cmp(&b.0));
                    if merged_weekly.len() > MAX_WEEKLY_PROPAGANDA_BUCKETS {
                        let overflow = merged_weekly.len() - MAX_WEEKLY_PROPAGANDA_BUCKETS;
                        merged_weekly.drain(0..overflow);
                    }
                    local.weekly_propaganda_counts.clear();
                    for entry in merged_weekly {
                        local.weekly_propaganda_counts.push_back(entry);
                    }

                    let mut known_conversations: HashSet<ConversationId> =
                        HashSet::with_capacity(local.conversations.len());
                    for conv in &local.conversations {
                        known_conversations.insert(conv.clone());
                    }
                    for conv in incoming.conversations {
                        if known_conversations.insert(conv.clone()) {
                            local.conversations.push(conv);
                        }
                    }
                    local.conversation_count = local.conversations.len();

                    local.trust_level = local.trust_level.min(incoming.trust_level);
                    local.rating = local.rating.min(incoming.rating);
                    local.is_trusted = local.is_trusted && incoming.is_trusted;

                    if trend_severity(&incoming.trend) > trend_severity(&local.trend) {
                        local.trend = incoming.trend;
                    }

                    if local.inferred_age.is_none() {
                        local.inferred_age = incoming.inferred_age;
                    }

                    let local_average = local.average_severity();
                    let merged_average = local_average.max(incoming_average);
                    local.severity_count = local.severity_count.max(incoming_severity_count);
                    if local.severity_count == 0 {
                        local.severity_sum = 0.0;
                    } else {
                        local.severity_sum = merged_average * local.severity_count as f32;
                    }
                    if local.propaganda_event_count > 0 {
                        local.update_propaganda_score();
                    }
                }
                None => {
                    self.profiles.insert(incoming.sender_id.clone(), incoming);
                }
            }
        }
        self.enforce_profile_limit();
    }

    /// Imports profiles from wire-format state, replacing existing profiles with the same sender ID.
    pub fn import_wire_state(&mut self, state: ContactProfilerWireState) {
        let mut profiles = Vec::with_capacity(state.profiles.len());
        for p in state.profiles {
            profiles.push(ContactProfile::from(p));
        }
        self.import(ContactProfilerState { profiles });
    }

    /// Merges profiles from wire-format state, taking the most cautious values for conflicts.
    pub fn merge_import_wire_state(&mut self, state: ContactProfilerWireState) {
        let mut profiles = Vec::with_capacity(state.profiles.len());
        for p in state.profiles {
            profiles.push(ContactProfile::from(p));
        }
        self.merge_import(ContactProfilerState { profiles });
    }

    /// Removes profiles not seen since the cutoff and prunes stale active-day entries.
    pub fn cleanup(&mut self, cutoff_ms: u64) {
        let cutoff_day = (cutoff_ms / DAY_MS) as u32;
        self.profiles.retain(|_, p| {
            if p.last_seen_ms < cutoff_ms {
                return false;
            }
            p.active_days
                .retain(|&d| d >= cutoff_day.saturating_sub(90));
            true
        });
    }

    fn ensure_capacity_for_sender(&mut self, sender_id: &str) {
        if self.profiles.contains_key(sender_id) {
            return;
        }

        self.enforce_profile_limit_for_incoming(sender_id);
    }

    fn enforce_profile_limit(&mut self) {
        while self.profiles.len() > self.max_profiles {
            if self.evict_oldest_profile(None).is_none() {
                break;
            }
        }
    }

    fn enforce_profile_limit_for_incoming(&mut self, incoming_sender_id: &str) {
        while self.profiles.len() >= self.max_profiles {
            if self
                .evict_oldest_profile(Some(incoming_sender_id))
                .is_none()
            {
                break;
            }
        }
    }

    fn evict_oldest_profile(
        &mut self,
        protected_sender_id: Option<&str>,
    ) -> Option<ContactProfile> {
        let mut oldest_sender: Option<SenderId> = None;
        let mut best_risk_band = u8::MAX;
        let mut best_last_seen = u64::MAX;
        let mut best_first_seen = u64::MAX;
        let mut best_id: Option<&str> = None;
        for (sender_id, profile) in &self.profiles {
            if Some(&**sender_id) == protected_sender_id {
                continue;
            }
            let risk_band = if profile.risk_score() >= 0.75 {
                2u8
            } else if profile.risk_score() >= 0.45 {
                1u8
            } else {
                0u8
            };
            let cmp = risk_band
                .cmp(&best_risk_band)
                .then_with(|| profile.last_seen_ms.cmp(&best_last_seen))
                .then_with(|| profile.first_seen_ms.cmp(&best_first_seen))
                .then_with(|| (**sender_id).cmp(best_id.unwrap_or("")));
            if cmp == std::cmp::Ordering::Less || oldest_sender.is_none() {
                best_risk_band = risk_band;
                best_last_seen = profile.last_seen_ms;
                best_first_seen = profile.first_seen_ms;
                best_id = Some(&**sender_id);
                oldest_sender = Some(sender_id.clone());
            }
        }

        let key = oldest_sender?;
        self.profiles.remove(&key)
    }
}

/// Holds a snapshot of all contact profiles for export or import.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactProfilerState {
    pub profiles: Vec<ContactProfile>,
}

#[cfg(test)]
mod tests {
    use super::super::events::{ContextEvent, EventKind};
    use super::*;

    fn make_event(sender: &str, conv: &str, kind: EventKind, ts: u64) -> ContextEvent {
        ContextEvent {
            event_id: 0,
            timestamp_ms: ts,
            sender_id: sender.into(),
            conversation_id: conv.into(),
            kind,
            confidence: 0.8,
            subtype: None,
            content_hash: None,
        }
    }

    fn all_event_kinds() -> Vec<EventKind> {
        vec![
            EventKind::Flattery,
            EventKind::GiftOffer,
            EventKind::SecrecyRequest,
            EventKind::PlatformSwitch,
            EventKind::PersonalInfoRequest,
            EventKind::PhotoRequest,
            EventKind::VideoCallRequest,
            EventKind::FinancialGrooming,
            EventKind::MeetingRequest,
            EventKind::SexualContent,
            EventKind::AgeInappropriate,
            EventKind::Insult,
            EventKind::Denigration,
            EventKind::HarmEncouragement,
            EventKind::PhysicalThreat,
            EventKind::RumorSpreading,
            EventKind::Exclusion,
            EventKind::Mockery,
            EventKind::GuiltTripping,
            EventKind::Gaslighting,
            EventKind::EmotionalBlackmail,
            EventKind::PeerPressure,
            EventKind::LoveBombing,
            EventKind::Darvo,
            EventKind::Devaluation,
            EventKind::SuicidalIdeation,
            EventKind::Hopelessness,
            EventKind::FarewellMessage,
            EventKind::DoxxingAttempt,
            EventKind::ScreenshotThreat,
            EventKind::HateSpeech,
            EventKind::LocationRequest,
            EventKind::MoneyOffer,
            EventKind::PiiSelfDisclosure,
            EventKind::CasualMeetingRequest,
            EventKind::DareChallenge,
            EventKind::SuicideCoercion,
            EventKind::FalseConsensus,
            EventKind::DebtCreation,
            EventKind::ReputationThreat,
            EventKind::IdentityErosion,
            EventKind::NetworkPoisoning,
            EventKind::FakeVulnerability,
            EventKind::NormalConversation,
            EventKind::TrustedContact,
            EventKind::DefenseOfVictim,
        ]
    }

    #[test]
    fn new_contact_detected() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event("stranger", "conv_1", EventKind::Flattery, 1000));

        assert!(profiler.is_new_contact("stranger"));
        assert!(profiler.is_new_contact("unknown_person"));
    }

    #[test]
    fn established_contact_not_new() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "friend",
            "conv_1",
            EventKind::NormalConversation,
            0,
        ));

        profiler.record_event(&make_event(
            "friend",
            "conv_1",
            EventKind::NormalConversation,
            3 * 24 * 60 * 60 * 1000,
        ));

        assert!(!profiler.is_new_contact("friend"));
    }

    #[test]
    fn grooming_events_tracked() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event("predator", "conv_1", EventKind::Flattery, 1000));
        profiler.record_event(&make_event(
            "predator",
            "conv_1",
            EventKind::GiftOffer,
            2000,
        ));
        profiler.record_event(&make_event(
            "predator",
            "conv_1",
            EventKind::SecrecyRequest,
            3000,
        ));

        let profile = profiler.profile("predator").unwrap();
        assert_eq!(profile.grooming_event_count, 3);
        assert!(profile.risk_score() > 0.0);
    }

    #[test]
    fn trusted_contact_lower_risk() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event("person", "conv_1", EventKind::Flattery, 1000));
        profiler.record_event(&make_event("person", "conv_1", EventKind::GiftOffer, 2000));

        let risk_before = profiler.profile("person").unwrap().risk_score();

        profiler.mark_trusted("person");

        let risk_after = profiler.profile("person").unwrap().risk_score();
        assert!(risk_after < risk_before);
    }

    #[test]
    fn multi_conversation_predator_detected() {
        let mut profiler = ContactProfiler::new();

        for i in 0..5 {
            profiler.record_event(&make_event(
                "predator",
                &format!("conv_{i}"),
                EventKind::Flattery,
                i as u64 * 1000,
            ));
        }

        profiler.record_event(&make_event(
            "predator",
            "conv_0",
            EventKind::SecrecyRequest,
            6000,
        ));
        profiler.record_event(&make_event(
            "predator",
            "conv_1",
            EventKind::PhotoRequest,
            7000,
        ));
        profiler.record_event(&make_event(
            "predator",
            "conv_2",
            EventKind::GiftOffer,
            8000,
        ));

        assert!(profiler.contacts_many_minors("predator"));

        let signals = profiler.check_anomalies("predator", true);
        assert!(!signals.is_empty());
        assert!(signals.iter().any(|s| s.score >= 0.8));
    }

    #[test]
    fn predator_pattern_not_emitted_for_non_minor_account() {
        let mut profiler = ContactProfiler::new();

        for i in 0..5 {
            profiler.record_event(&make_event(
                "predator",
                &format!("conv_{i}"),
                EventKind::Flattery,
                i as u64 * 1000,
            ));
        }
        profiler.record_event(&make_event(
            "predator",
            "conv_0",
            EventKind::SecrecyRequest,
            6000,
        ));
        profiler.record_event(&make_event(
            "predator",
            "conv_1",
            EventKind::PhotoRequest,
            7000,
        ));
        profiler.record_event(&make_event(
            "predator",
            "conv_2",
            EventKind::GiftOffer,
            8000,
        ));

        let signals = profiler.check_anomalies("predator", false);
        assert!(
            !signals
                .iter()
                .any(|signal| signal.reason_code == "conversation.contact.multi_conversation_predator_pattern"),
            "predator pattern should be minor-account only"
        );
    }

    #[test]
    fn anomalies_for_new_risky_contact() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event("stranger", "conv_1", EventKind::Flattery, 1000));
        profiler.record_event(&make_event(
            "stranger",
            "conv_1",
            EventKind::SecrecyRequest,
            2000,
        ));
        profiler.record_event(&make_event(
            "stranger",
            "conv_1",
            EventKind::PhotoRequest,
            3000,
        ));

        let signals = profiler.check_anomalies("stranger", true);
        assert!(
            !signals.is_empty(),
            "Expected anomaly signal for risky new contact"
        );
    }

    #[test]
    fn new_risky_contact_uses_manipulation_when_profile_is_manipulation_dominant() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "controller",
            "conv_1",
            EventKind::Gaslighting,
            1000,
        ));
        profiler.record_event(&make_event(
            "controller",
            "conv_1",
            EventKind::DebtCreation,
            2000,
        ));
        profiler.record_event(&make_event(
            "controller",
            "conv_1",
            EventKind::NetworkPoisoning,
            3000,
        ));

        let signals = profiler.check_anomalies("controller", true);
        assert!(
            signals
                .iter()
                .any(|signal| signal.threat_type == ThreatType::Manipulation),
            "manipulation-dominant new contact should emit manipulation anomaly: {signals:?}"
        );
    }

    #[test]
    fn new_risky_contact_uses_propaganda_when_profile_is_propaganda_dominant() {
        let mut profiler = ContactProfiler::new();
        for i in 0..6 {
            let mut event = make_event(
                "propagandist",
                "conv_1",
                EventKind::PropagandaNarrative,
                1000 + i * 1000,
            );
            event.subtype = Some("war_denial".to_string());
            profiler.record_event(&event);
        }

        let signals = profiler.check_anomalies("propagandist", true);
        assert!(
            signals
                .iter()
                .any(|signal| signal.threat_type == ThreatType::Propaganda),
            "propaganda-dominant new contact should emit propaganda anomaly: {signals:?}"
        );
    }

    #[test]
    fn cleanup_removes_old_contacts() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "old",
            "conv_1",
            EventKind::NormalConversation,
            1000,
        ));
        profiler.record_event(&make_event(
            "recent",
            "conv_2",
            EventKind::NormalConversation,
            50000,
        ));

        profiler.cleanup(10000);

        assert!(profiler.profile("old").is_none());
        assert!(profiler.profile("recent").is_some());
    }

    #[test]
    fn contacts_sorted_by_risk() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "safe",
            "conv_1",
            EventKind::NormalConversation,
            1000,
        ));
        profiler.record_event(&make_event("risky", "conv_1", EventKind::Flattery, 1000));
        profiler.record_event(&make_event(
            "risky",
            "conv_1",
            EventKind::SecrecyRequest,
            2000,
        ));
        profiler.record_event(&make_event(
            "risky",
            "conv_1",
            EventKind::PhotoRequest,
            3000,
        ));

        let sorted = profiler.contacts_by_risk();
        assert_eq!(sorted[0].sender_id, "risky");
    }

    #[test]
    fn set_inferred_age_works() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "user_a",
            "conv_1",
            EventKind::NormalConversation,
            1000,
        ));
        profiler.record_event(&make_event(
            "user_a",
            "conv_1",
            EventKind::NormalConversation,
            1100,
        ));
        profiler.set_inferred_age("user_a", 25);

        let profile = profiler.profile("user_a").unwrap();
        assert_eq!(profile.inferred_age, Some(25));
    }

    #[test]
    fn set_inferred_age_first_wins() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "user_a",
            "conv_1",
            EventKind::NormalConversation,
            1000,
        ));
        profiler.record_event(&make_event(
            "user_a",
            "conv_1",
            EventKind::NormalConversation,
            1100,
        ));
        profiler.set_inferred_age("user_a", 25);
        profiler.set_inferred_age("user_a", 30);

        let profile = profiler.profile("user_a").unwrap();
        assert_eq!(profile.inferred_age, Some(25));
    }

    #[test]
    fn set_inferred_age_rejects_implausible() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "user_a",
            "conv_1",
            EventKind::NormalConversation,
            1000,
        ));
        profiler.record_event(&make_event(
            "user_a",
            "conv_1",
            EventKind::NormalConversation,
            1100,
        ));
        profiler.set_inferred_age("user_a", 3);

        assert_eq!(profiler.profile("user_a").unwrap().inferred_age, None);

        profiler.set_inferred_age("user_a", 150);

        assert_eq!(profiler.profile("user_a").unwrap().inferred_age, None);
    }

    #[test]
    fn set_inferred_age_requires_minimal_history() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "one_shot",
            "conv_1",
            EventKind::NormalConversation,
            1000,
        ));
        profiler.set_inferred_age("one_shot", 24);
        assert_eq!(profiler.profile("one_shot").unwrap().inferred_age, None);
    }

    #[test]
    fn age_gap_adult_to_child() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "adult",
            "conv_1",
            EventKind::NormalConversation,
            1000,
        ));
        profiler.record_event(&make_event(
            "adult",
            "conv_1",
            EventKind::NormalConversation,
            1100,
        ));
        profiler.set_inferred_age("adult", 30);

        let signals = profiler.check_age_gap("adult", Some(12));
        assert!(
            !signals.is_empty(),
            "30yo talking to 12yo should trigger age gap"
        );
        assert_eq!(signals[0].threat_type, ThreatType::Grooming);
    }

    #[test]
    fn age_gap_with_grooming_signals_boosts_score() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event("predator", "conv_1", EventKind::Flattery, 1000));
        profiler.record_event(&make_event(
            "predator",
            "conv_1",
            EventKind::SecrecyRequest,
            2000,
        ));
        profiler.set_inferred_age("predator", 35);

        let signals = profiler.check_age_gap("predator", Some(11));
        assert!(!signals.is_empty());

        assert!(
            signals[0].score >= 0.6,
            "Age gap + grooming should have high score, got {}",
            signals[0].score
        );
    }

    #[test]
    fn no_age_gap_between_peers() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "teen",
            "conv_1",
            EventKind::NormalConversation,
            1000,
        ));
        profiler.record_event(&make_event(
            "teen",
            "conv_1",
            EventKind::NormalConversation,
            1100,
        ));
        profiler.set_inferred_age("teen", 14);

        let signals = profiler.check_age_gap("teen", Some(13));
        assert!(
            signals.is_empty(),
            "Small age gap between minors should not trigger"
        );
    }

    #[test]
    fn no_age_gap_without_holder_age() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "adult",
            "conv_1",
            EventKind::NormalConversation,
            1000,
        ));
        profiler.record_event(&make_event(
            "adult",
            "conv_1",
            EventKind::NormalConversation,
            1100,
        ));
        profiler.set_inferred_age("adult", 30);

        let signals = profiler.check_age_gap("adult", None);
        assert!(signals.is_empty(), "No holder age = no gap detection");
    }

    #[test]
    fn no_age_gap_trusted_contact() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "uncle",
            "conv_1",
            EventKind::NormalConversation,
            1000,
        ));
        profiler.record_event(&make_event(
            "uncle",
            "conv_1",
            EventKind::NormalConversation,
            1100,
        ));
        profiler.set_inferred_age("uncle", 40);
        profiler.mark_trusted("uncle");

        let signals = profiler.check_age_gap("uncle", Some(12));
        assert!(
            signals.is_empty(),
            "Trusted contacts should not trigger age gap"
        );
    }

    #[test]
    fn age_source_ml_inferred_reduces_age_gap_score() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event("ml_adult", "c1", EventKind::NormalConversation, 1000));
        profiler.record_event(&make_event("ml_adult", "c1", EventKind::NormalConversation, 2000));
        profiler.set_inferred_age_with_source("ml_adult", 30, AgeSource::MlInferred);

        let mut profiler2 = ContactProfiler::new();
        profiler2.record_event(&make_event("verified_adult", "c2", EventKind::NormalConversation, 1000));
        profiler2.record_event(&make_event("verified_adult", "c2", EventKind::NormalConversation, 2000));
        profiler2.set_inferred_age_with_source("verified_adult", 30, AgeSource::ParentVerified);

        let ml_signals = profiler.check_age_gap("ml_adult", Some(12));
        let verified_signals = profiler2.check_age_gap("verified_adult", Some(12));

        assert!(!ml_signals.is_empty());
        assert!(!verified_signals.is_empty());
        assert!(
            ml_signals[0].score < verified_signals[0].score,
            "ML-inferred ({}) should score lower than parent-verified ({})",
            ml_signals[0].score,
            verified_signals[0].score,
        );
    }

    #[test]
    fn age_source_parent_verified_overwrites_ml_inferred() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event("user", "c1", EventKind::NormalConversation, 1000));
        profiler.record_event(&make_event("user", "c1", EventKind::NormalConversation, 2000));
        profiler.set_inferred_age_with_source("user", 25, AgeSource::MlInferred);
        assert_eq!(profiler.profile("user").unwrap().inferred_age, Some(25));
        assert_eq!(profiler.profile("user").unwrap().age_source, AgeSource::MlInferred);

        profiler.set_inferred_age_with_source("user", 28, AgeSource::ParentVerified);
        assert_eq!(profiler.profile("user").unwrap().inferred_age, Some(28));
        assert_eq!(profiler.profile("user").unwrap().age_source, AgeSource::ParentVerified);
    }

    #[test]
    fn age_source_ml_does_not_overwrite_user_reported() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event("user", "c1", EventKind::NormalConversation, 1000));
        profiler.record_event(&make_event("user", "c1", EventKind::NormalConversation, 2000));
        profiler.set_inferred_age("user", 25);
        assert_eq!(profiler.profile("user").unwrap().age_source, AgeSource::UserReported);

        profiler.set_inferred_age_with_source("user", 30, AgeSource::MlInferred);
        assert_eq!(
            profiler.profile("user").unwrap().inferred_age,
            Some(25),
            "ML should not overwrite user-reported age"
        );
    }

    #[test]
    fn new_contact_starts_at_50_rating() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "alice",
            "conv_1",
            EventKind::NormalConversation,
            1000,
        ));
        let profile = profiler.profile("alice").unwrap();
        assert!(
            (profile.rating - 50.3).abs() < 0.01,
            "New contact rating should be ~50.3, got {}",
            profile.rating
        );
    }

    #[test]
    fn hostile_events_decrease_rating() {
        let mut profiler = ContactProfiler::new();
        for i in 0..5 {
            profiler.record_event(&make_event("bully", "conv_1", EventKind::Insult, i * 1000));
        }
        let profile = profiler.profile("bully").unwrap();
        assert!(
            profile.rating < 42.0,
            "5 insults should drop rating below 42, got {}",
            profile.rating
        );
    }

    #[test]
    fn supportive_events_increase_rating() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "friend",
            "conv_1",
            EventKind::DefenseOfVictim,
            1000,
        ));
        let profile = profiler.profile("friend").unwrap();
        assert!(
            profile.rating > 50.0,
            "Defense should increase rating above 50, got {}",
            profile.rating
        );
    }

    #[test]
    fn rating_clamped_0_100() {
        let mut profiler = ContactProfiler::new();
        for i in 0..20 {
            profiler.record_event(&make_event(
                "attacker",
                "conv_1",
                EventKind::SuicideCoercion,
                i * 1000,
            ));
        }
        let profile = profiler.profile("attacker").unwrap();
        assert!(
            profile.rating >= 0.0,
            "Rating should not go below 0, got {}",
            profile.rating
        );
        assert!(
            profile.rating <= 100.0,
            "Rating should not exceed 100, got {}",
            profile.rating
        );
    }

    #[test]
    fn trust_decays_on_hostile_events() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "friend",
            "conv_1",
            EventKind::NormalConversation,
            1000,
        ));
        profiler.mark_trusted("friend");
        assert_eq!(profiler.profile("friend").unwrap().trust_level, 1.0);

        for i in 0..5 {
            profiler.record_event(&make_event(
                "friend",
                "conv_1",
                EventKind::Insult,
                (i + 2) * 1000,
            ));
        }
        let profile = profiler.profile("friend").unwrap();
        assert!(
            profile.trust_level < 1.0,
            "Trust should decay after insults, got {}",
            profile.trust_level
        );
    }

    #[test]
    fn trust_decay_removes_trusted_flag() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "friend",
            "conv_1",
            EventKind::NormalConversation,
            1000,
        ));
        profiler.mark_trusted("friend");
        assert!(profiler.profile("friend").unwrap().is_trusted);

        for i in 0..10 {
            profiler.record_event(&make_event(
                "friend",
                "conv_1",
                EventKind::PhysicalThreat,
                (i + 2) * 1000,
            ));
        }
        let profile = profiler.profile("friend").unwrap();
        assert!(
            !profile.is_trusted,
            "10 high-severity threats should remove trusted flag"
        );
        assert!(
            profile.trust_level < 0.7,
            "Trust level should be below 0.7, got {}",
            profile.trust_level
        );
    }

    #[test]
    fn propaganda_trust_decay_uses_half_rate() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "friend",
            "conv_1",
            EventKind::NormalConversation,
            1_000,
        ));
        profiler.mark_trusted("friend");

        profiler.record_event(&make_event(
            "friend",
            "conv_1",
            EventKind::SuspiciousSource,
            2_000,
        ));

        let profile = profiler.profile("friend").unwrap();
        let expected = 1.0 - EventKind::SuspiciousSource.severity() * 0.15 * 0.5;
        assert!(
            (profile.trust_level - expected).abs() < 1e-6,
            "Expected trust_level {}, got {}",
            expected,
            profile.trust_level
        );
    }

    #[test]
    fn propaganda_weekly_counts_and_fingerprints_recorded() {
        let mut profiler = ContactProfiler::new();

        let mut event_a = make_event("agent", "conv_1", EventKind::PropagandaNarrative, 1_000);
        event_a.subtype = Some("war_denial".to_string());
        event_a.content_hash = Some(11);
        profiler.record_event(&event_a);

        let mut event_b = make_event("agent", "conv_1", EventKind::PropagandaNarrative, 2_000);
        event_b.subtype = Some("war_denial".to_string());
        event_b.content_hash = Some(11);
        profiler.record_event(&event_b);

        let mut event_c = make_event(
            "agent",
            "conv_1",
            EventKind::PropagandaNarrative,
            WEEK_MS + 3_000,
        );
        event_c.subtype = Some("capitulation".to_string());
        event_c.content_hash = Some(22);
        profiler.record_event(&event_c);

        let profile = profiler.profile("agent").unwrap();
        assert_eq!(profile.weekly_propaganda_counts.len(), 2);
        assert_eq!(profile.weekly_propaganda_counts[0].1, 2);
        assert_eq!(profile.weekly_propaganda_counts[1].1, 1);
        assert_eq!(profile.message_fingerprints.len(), 3);
        assert_eq!(profile.message_fingerprints[0], 11);
        assert_eq!(profile.message_fingerprints[1], 11);
        assert_eq!(profile.message_fingerprints[2], 22);
    }

    #[test]
    fn propaganda_fingerprint_dedup_same_message_marker() {
        let mut profiler = ContactProfiler::new();

        let mut event_a = make_event("agent", "conv_1", EventKind::PropagandaNarrative, 10_000);
        event_a.subtype = Some("war_denial".to_string());
        event_a.content_hash = Some(999);
        profiler.record_event(&event_a);

        let mut event_b = make_event("agent", "conv_1", EventKind::SuspiciousSource, 10_000);
        event_b.content_hash = Some(999);
        profiler.record_event(&event_b);

        let profile = profiler.profile("agent").unwrap();
        let count = profile
            .message_fingerprints
            .iter()
            .filter(|&&fingerprint| fingerprint == 999)
            .count();
        assert_eq!(
            count, 1,
            "Same message marker should not duplicate fingerprint"
        );
    }

    #[test]
    fn propaganda_weekly_counts_keep_chronological_order() {
        let mut profiler = ContactProfiler::new();

        let mut newer = make_event(
            "agent",
            "conv_1",
            EventKind::PropagandaNarrative,
            WEEK_MS + 1_000,
        );
        newer.subtype = Some("war_denial".to_string());
        profiler.record_event(&newer);

        let mut older = make_event("agent", "conv_1", EventKind::PropagandaNarrative, 1_000);
        older.subtype = Some("war_denial".to_string());
        profiler.record_event(&older);

        let profile = profiler.profile("agent").unwrap();
        assert_eq!(profile.weekly_propaganda_counts.len(), 2);
        assert!(
            profile.weekly_propaganda_counts[0].0 < profile.weekly_propaganda_counts[1].0,
            "Weekly propaganda buckets should stay chronological"
        );
    }

    #[test]
    fn propaganda_score_recomputes_when_concentration_drops() {
        let mut profiler = ContactProfiler::new();

        for i in 0..10 {
            let mut event = make_event(
                "agent",
                "conv_1",
                EventKind::PropagandaNarrative,
                1_000 + i * 1_000,
            );
            event.subtype = Some("war_denial".to_string());
            event.content_hash = Some(500 + i);
            profiler.record_event(&event);
        }

        let score_before = profiler.profile("agent").unwrap().propaganda_score;

        for i in 0..30 {
            profiler.record_event(&make_event(
                "agent",
                "conv_1",
                EventKind::NormalConversation,
                50_000 + i * 1_000,
            ));
        }

        let score_after = profiler.profile("agent").unwrap().propaganda_score;
        assert!(
            score_after < score_before,
            "Expected propaganda score to drop after concentration decreases: before={score_before}, after={score_after}"
        );
    }

    #[test]
    fn mark_trusted_sets_full_trust() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "uncle",
            "conv_1",
            EventKind::NormalConversation,
            1000,
        ));
        profiler.mark_trusted("uncle");
        let profile = profiler.profile("uncle").unwrap();
        assert_eq!(profile.trust_level, 1.0);
        assert!(profile.is_trusted);
    }

    #[test]
    fn circle_tier_new_under_14_days() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "newbie",
            "conv_1",
            EventKind::NormalConversation,
            1000,
        ));
        assert_eq!(
            profiler.profile("newbie").unwrap().circle_tier,
            CircleTier::New
        );
    }

    #[test]
    fn circle_tier_inner_frequent() {
        let mut profiler = ContactProfiler::new();
        let start = 0u64;
        for day in 0..15 {
            for msg in 0..10 {
                profiler.record_event(&make_event(
                    "bestie",
                    "conv_1",
                    EventKind::NormalConversation,
                    start + day * DAY_MS + msg * 1000,
                ));
            }
        }
        assert_eq!(
            profiler.profile("bestie").unwrap().circle_tier,
            CircleTier::Inner
        );
    }

    #[test]
    fn circle_tier_regular_weekly() {
        let mut profiler = ContactProfiler::new();
        for day in (0..30).step_by(2) {
            profiler.record_event(&make_event(
                "classmate",
                "conv_1",
                EventKind::NormalConversation,
                day * DAY_MS,
            ));
        }
        assert_eq!(
            profiler.profile("classmate").unwrap().circle_tier,
            CircleTier::Regular
        );
    }

    #[test]
    fn circle_tier_occasional_rare() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "distant",
            "conv_1",
            EventKind::NormalConversation,
            0,
        ));
        profiler.record_event(&make_event(
            "distant",
            "conv_1",
            EventKind::NormalConversation,
            30 * DAY_MS,
        ));
        profiler.record_event(&make_event(
            "distant",
            "conv_1",
            EventKind::NormalConversation,
            60 * DAY_MS,
        ));
        assert_eq!(
            profiler.profile("distant").unwrap().circle_tier,
            CircleTier::Occasional
        );
    }

    #[test]
    fn snapshot_created_on_first_event() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "alice",
            "conv_1",
            EventKind::NormalConversation,
            1000,
        ));
        let profile = profiler.profile("alice").unwrap();
        assert!(profile.current_snapshot.is_some());
        assert_eq!(profile.current_snapshot.as_ref().unwrap().total_messages, 1);
    }

    #[test]
    fn snapshot_finalized_after_week() {
        let mut profiler = ContactProfiler::new();
        for i in 0..5 {
            profiler.record_event(&make_event(
                "alice",
                "conv_1",
                EventKind::NormalConversation,
                i * 1000,
            ));
        }
        assert_eq!(profiler.profile("alice").unwrap().weekly_snapshots.len(), 0);

        profiler.record_event(&make_event(
            "alice",
            "conv_1",
            EventKind::NormalConversation,
            WEEK_MS + 1000,
        ));
        assert_eq!(profiler.profile("alice").unwrap().weekly_snapshots.len(), 1);
        assert_eq!(
            profiler.profile("alice").unwrap().weekly_snapshots[0].total_messages,
            5
        );
    }

    #[test]
    fn max_26_weekly_snapshots() {
        let mut profiler = ContactProfiler::new();
        for week in 0..30 {
            profiler.record_event(&make_event(
                "alice",
                "conv_1",
                EventKind::NormalConversation,
                week * WEEK_MS + 1000,
            ));
        }
        let profile = profiler.profile("alice").unwrap();
        assert!(
            profile.weekly_snapshots.len() <= MAX_SNAPSHOTS,
            "Should not exceed {} snapshots, got {}",
            MAX_SNAPSHOTS,
            profile.weekly_snapshots.len()
        );
    }

    #[test]
    fn trend_stable_with_consistent_behavior() {
        let mut profiler = ContactProfiler::new();
        for week in 0..5 {
            for msg in 0..10 {
                profiler.record_event(&make_event(
                    "stable",
                    "conv_1",
                    EventKind::NormalConversation,
                    week * WEEK_MS + msg * 1000,
                ));
            }
        }
        profiler.record_event(&make_event(
            "stable",
            "conv_1",
            EventKind::NormalConversation,
            5 * WEEK_MS + 1000,
        ));
        assert_eq!(
            profiler.profile("stable").unwrap().trend,
            BehavioralTrend::Stable
        );
    }

    #[test]
    fn trend_gradual_worsening_detected() {
        let mut profiler = ContactProfiler::new();
        for week in 0..3 {
            for msg in 0..10 {
                profiler.record_event(&make_event(
                    "masha",
                    "conv_1",
                    EventKind::NormalConversation,
                    week * WEEK_MS + msg * 1000,
                ));
            }
        }
        for week in 3..5 {
            for msg in 0..8 {
                profiler.record_event(&make_event(
                    "masha",
                    "conv_1",
                    EventKind::NormalConversation,
                    week * WEEK_MS + msg * 1000,
                ));
            }
            for msg in 8..10 {
                profiler.record_event(&make_event(
                    "masha",
                    "conv_1",
                    EventKind::Insult,
                    week * WEEK_MS + msg * 1000,
                ));
            }
        }
        profiler.record_event(&make_event(
            "masha",
            "conv_1",
            EventKind::Insult,
            5 * WEEK_MS + 1000,
        ));
        let trend = profiler.profile("masha").unwrap().trend;
        assert!(
            trend == BehavioralTrend::GradualWorsening || trend == BehavioralTrend::RapidWorsening,
            "Expected worsening trend, got {:?}",
            trend
        );
    }

    #[test]
    fn trend_rapid_worsening_detected() {
        let mut profiler = ContactProfiler::new();
        for week in 0..3 {
            for msg in 0..10 {
                profiler.record_event(&make_event(
                    "rapid",
                    "conv_1",
                    EventKind::NormalConversation,
                    week * WEEK_MS + msg * 1000,
                ));
            }
        }
        for week in 3..5 {
            for msg in 0..6 {
                profiler.record_event(&make_event(
                    "rapid",
                    "conv_1",
                    EventKind::NormalConversation,
                    week * WEEK_MS + msg * 1000,
                ));
            }
            for msg in 6..10 {
                profiler.record_event(&make_event(
                    "rapid",
                    "conv_1",
                    EventKind::Insult,
                    week * WEEK_MS + msg * 1000,
                ));
            }
        }
        profiler.record_event(&make_event(
            "rapid",
            "conv_1",
            EventKind::Insult,
            5 * WEEK_MS + 1000,
        ));
        assert_eq!(
            profiler.profile("rapid").unwrap().trend,
            BehavioralTrend::RapidWorsening
        );
    }

    #[test]
    fn trend_role_reversal_detected() {
        let mut profiler = ContactProfiler::new();
        for week in 0..3 {
            for msg in 0..6 {
                profiler.record_event(&make_event(
                    "reversal",
                    "conv_1",
                    EventKind::NormalConversation,
                    week * WEEK_MS + msg * 1000,
                ));
            }
            for msg in 6..10 {
                profiler.record_event(&make_event(
                    "reversal",
                    "conv_1",
                    EventKind::DefenseOfVictim,
                    week * WEEK_MS + msg * 1000,
                ));
            }
        }
        for week in 3..5 {
            for msg in 0..6 {
                profiler.record_event(&make_event(
                    "reversal",
                    "conv_1",
                    EventKind::NormalConversation,
                    week * WEEK_MS + msg * 1000,
                ));
            }
            for msg in 6..10 {
                profiler.record_event(&make_event(
                    "reversal",
                    "conv_1",
                    EventKind::Insult,
                    week * WEEK_MS + msg * 1000,
                ));
            }
        }
        profiler.record_event(&make_event(
            "reversal",
            "conv_1",
            EventKind::Insult,
            5 * WEEK_MS + 1000,
        ));
        assert_eq!(
            profiler.profile("reversal").unwrap().trend,
            BehavioralTrend::RoleReversal
        );
    }

    #[test]
    fn shift_signal_generated_for_role_reversal() {
        let mut profiler = ContactProfiler::new();
        for week in 0..3 {
            for msg in 0..6 {
                profiler.record_event(&make_event(
                    "turner",
                    "conv_1",
                    EventKind::NormalConversation,
                    week * WEEK_MS + msg * 1000,
                ));
            }
            for msg in 6..10 {
                profiler.record_event(&make_event(
                    "turner",
                    "conv_1",
                    EventKind::DefenseOfVictim,
                    week * WEEK_MS + msg * 1000,
                ));
            }
        }
        for week in 3..5 {
            for msg in 0..6 {
                profiler.record_event(&make_event(
                    "turner",
                    "conv_1",
                    EventKind::NormalConversation,
                    week * WEEK_MS + msg * 1000,
                ));
            }
            for msg in 6..10 {
                profiler.record_event(&make_event(
                    "turner",
                    "conv_1",
                    EventKind::Insult,
                    week * WEEK_MS + msg * 1000,
                ));
            }
        }
        profiler.record_event(&make_event(
            "turner",
            "conv_1",
            EventKind::Insult,
            5 * WEEK_MS + 1000,
        ));

        let signals = profiler.check_behavioral_shift("turner");
        assert!(
            !signals.is_empty(),
            "Role reversal should generate a behavioral shift signal"
        );
        assert_eq!(signals[0].threat_type, ThreatType::Bullying);
        assert!(signals[0].score >= 0.6);
    }

    #[test]
    fn shift_signal_boosted_for_inner_circle() {
        let mut profiler = ContactProfiler::new();
        for day in 0..15 {
            for msg in 0..10 {
                let week = day / 7;
                let ts = day as u64 * DAY_MS + msg * 1000;
                let kind = if week < 2 {
                    if msg < 6 {
                        EventKind::NormalConversation
                    } else {
                        EventKind::DefenseOfVictim
                    }
                } else {
                    EventKind::NormalConversation
                };
                profiler.record_event(&make_event("inner_friend", "conv_1", kind, ts));
            }
        }
        for day in 21..35 {
            for msg in 0..10 {
                let ts = day as u64 * DAY_MS + msg * 1000;
                let kind = if msg < 6 {
                    EventKind::NormalConversation
                } else {
                    EventKind::Insult
                };
                profiler.record_event(&make_event("inner_friend", "conv_1", kind, ts));
            }
        }
        profiler.record_event(&make_event(
            "inner_friend",
            "conv_1",
            EventKind::Insult,
            35 * DAY_MS + 1000,
        ));

        let profile = profiler.profile("inner_friend").unwrap();
        assert_eq!(profile.circle_tier, CircleTier::Inner);

        let signals = profiler.check_behavioral_shift("inner_friend");
        if !signals.is_empty() {
            assert!(
                signals[0].score >= 0.45,
                "Inner circle should boost signal score, got {}",
                signals[0].score
            );
        }
    }

    #[test]
    fn backward_compat_old_state_import() {
        let mut profiler = ContactProfiler::new();
        let old_json = r#"{"profiles":[{
            "sender_id":"alice",
            "first_seen_ms":1000,
            "last_seen_ms":2000,
            "total_messages":5,
            "conversation_count":1,
            "conversations":["conv_1"],
            "grooming_event_count":0,
            "bullying_event_count":0,
            "manipulation_event_count":0,
            "is_trusted":true,
            "severity_sum":0.0,
            "severity_count":0
        }]}"#;
        let state: ContactProfilerState = serde_json::from_str(old_json).unwrap();
        profiler.import(state);

        let profile = profiler.profile("alice").unwrap();
        assert_eq!(profile.trust_level, 1.0);
        assert_eq!(profile.rating, 50.0);
        assert_eq!(profile.circle_tier, CircleTier::New);
        assert_eq!(profile.trend, BehavioralTrend::Stable);
    }

    #[test]
    fn scenario_friend_to_bully_over_3_months() {
        let mut profiler = ContactProfiler::new();
        let week = WEEK_MS;

        for w in 0..4 {
            for msg in 0..10 {
                profiler.record_event(&make_event(
                    "masha",
                    "conv_1",
                    EventKind::NormalConversation,
                    w * week + msg * 1000,
                ));
            }
        }
        let sept_rating = profiler.profile("masha").unwrap().rating;
        assert!(
            sept_rating > 50.0,
            "September: rating should be above 50, got {sept_rating}"
        );

        for w in 4..8 {
            for msg in 0..8 {
                profiler.record_event(&make_event(
                    "masha",
                    "conv_1",
                    EventKind::NormalConversation,
                    w * week + msg * 1000,
                ));
            }
            for msg in 8..10 {
                profiler.record_event(&make_event(
                    "masha",
                    "conv_1",
                    EventKind::Insult,
                    w * week + msg * 1000,
                ));
            }
        }
        let oct_rating = profiler.profile("masha").unwrap().rating;
        assert!(
            oct_rating < sept_rating,
            "October: rating should decrease: sept={sept_rating} oct={oct_rating}"
        );

        for w in 8..16 {
            for msg in 0..4 {
                profiler.record_event(&make_event(
                    "masha",
                    "conv_1",
                    EventKind::NormalConversation,
                    w * week + msg * 1000,
                ));
            }
            for msg in 4..10 {
                profiler.record_event(&make_event(
                    "masha",
                    "conv_1",
                    EventKind::Insult,
                    w * week + msg * 1000,
                ));
            }
        }
        profiler.record_event(&make_event(
            "masha",
            "conv_1",
            EventKind::Insult,
            16 * week + 1000,
        ));

        let profile = profiler.profile("masha").unwrap();
        assert!(
            profile.rating < 30.0,
            "December: rating should be very low, got {}",
            profile.rating
        );
        assert!(
            profile.trend == BehavioralTrend::RapidWorsening
                || profile.trend == BehavioralTrend::GradualWorsening,
            "Should detect worsening trend, got {:?}",
            profile.trend
        );

        let signals = profiler.check_behavioral_shift("masha");
        assert!(
            !signals.is_empty(),
            "Should generate shift signal for friend-to-bully"
        );
    }

    #[test]
    fn scenario_trusted_adult_starts_grooming() {
        let mut profiler = ContactProfiler::new();
        for w in 0..4 {
            for msg in 0..10 {
                profiler.record_event(&make_event(
                    "coach",
                    "conv_1",
                    EventKind::NormalConversation,
                    w * WEEK_MS + msg * 1000,
                ));
            }
        }
        profiler.mark_trusted("coach");
        assert_eq!(profiler.profile("coach").unwrap().trust_level, 1.0);

        let baseline_rating = profiler.profile("coach").unwrap().rating;

        for w in 4..8 {
            for msg in 0..5 {
                profiler.record_event(&make_event(
                    "coach",
                    "conv_1",
                    EventKind::NormalConversation,
                    w * WEEK_MS + msg * 1000,
                ));
            }
            profiler.record_event(&make_event(
                "coach",
                "conv_1",
                EventKind::Flattery,
                w * WEEK_MS + 5000,
            ));
            profiler.record_event(&make_event(
                "coach",
                "conv_1",
                EventKind::PersonalInfoRequest,
                w * WEEK_MS + 6000,
            ));
            profiler.record_event(&make_event(
                "coach",
                "conv_1",
                EventKind::GiftOffer,
                w * WEEK_MS + 7000,
            ));
        }

        let profile = profiler.profile("coach").unwrap();
        assert!(
            profile.rating < baseline_rating,
            "Rating should decrease from grooming: baseline={baseline_rating} now={}",
            profile.rating
        );
        assert!(
            profile.trust_level >= 0.9,
            "Trust should remain high during grooming-only: {}",
            profile.trust_level
        );
    }

    #[test]
    fn scenario_trusted_adult_escalates_to_hostile() {
        let mut profiler = ContactProfiler::new();

        for w in 0..3 {
            for msg in 0..10 {
                profiler.record_event(&make_event(
                    "teacher",
                    "conv_1",
                    EventKind::NormalConversation,
                    w * WEEK_MS + msg * 1000,
                ));
            }
        }
        profiler.mark_trusted("teacher");

        for w in 3..6 {
            for msg in 0..5 {
                profiler.record_event(&make_event(
                    "teacher",
                    "conv_1",
                    EventKind::Gaslighting,
                    w * WEEK_MS + msg * 1000,
                ));
            }
            for msg in 5..10 {
                profiler.record_event(&make_event(
                    "teacher",
                    "conv_1",
                    EventKind::EmotionalBlackmail,
                    w * WEEK_MS + msg * 1000,
                ));
            }
        }
        profiler.record_event(&make_event(
            "teacher",
            "conv_1",
            EventKind::Gaslighting,
            6 * WEEK_MS + 1000,
        ));

        let profile = profiler.profile("teacher").unwrap();
        assert!(
            profile.trust_level < 0.3,
            "Trust should be destroyed after sustained hostility: {}",
            profile.trust_level
        );
        assert!(!profile.is_trusted, "Should no longer be trusted");
        assert!(
            profile.rating < 20.0,
            "Rating should be very low: {}",
            profile.rating
        );
    }

    #[test]
    fn scenario_recovery_after_hostility() {
        let mut profiler = ContactProfiler::new();

        for w in 0..3 {
            for msg in 0..10 {
                profiler.record_event(&make_event(
                    "recovering",
                    "conv_1",
                    EventKind::Insult,
                    w * WEEK_MS + msg * 1000,
                ));
            }
        }
        let hostile_rating = profiler.profile("recovering").unwrap().rating;

        for w in 3..8 {
            for msg in 0..10 {
                profiler.record_event(&make_event(
                    "recovering",
                    "conv_1",
                    EventKind::NormalConversation,
                    w * WEEK_MS + msg * 1000,
                ));
            }
        }
        profiler.record_event(&make_event(
            "recovering",
            "conv_1",
            EventKind::NormalConversation,
            8 * WEEK_MS + 1000,
        ));

        let profile = profiler.profile("recovering").unwrap();
        assert!(
            profile.rating > hostile_rating,
            "Rating should improve during recovery: hostile={hostile_rating} now={}",
            profile.rating
        );
        assert!(
            profile.trend == BehavioralTrend::Improving || profile.trend == BehavioralTrend::Stable,
            "Trend should show improvement or stability, got {:?}",
            profile.trend
        );
    }

    #[test]
    fn scenario_mixed_signals_alternating_weeks() {
        let mut profiler = ContactProfiler::new();

        for w in 0..8u64 {
            if w % 2 == 0 {
                for msg in 0..10 {
                    profiler.record_event(&make_event(
                        "mixed",
                        "conv_1",
                        EventKind::NormalConversation,
                        w * WEEK_MS + msg * 1000,
                    ));
                }
            } else {
                for msg in 0..4 {
                    profiler.record_event(&make_event(
                        "mixed",
                        "conv_1",
                        EventKind::NormalConversation,
                        w * WEEK_MS + msg * 1000,
                    ));
                }
                for msg in 4..10 {
                    profiler.record_event(&make_event(
                        "mixed",
                        "conv_1",
                        EventKind::Insult,
                        w * WEEK_MS + msg * 1000,
                    ));
                }
            }
        }
        profiler.record_event(&make_event(
            "mixed",
            "conv_1",
            EventKind::NormalConversation,
            8 * WEEK_MS + 1000,
        ));

        let profile = profiler.profile("mixed").unwrap();
        assert!(
            profile.rating < 60.0,
            "Mixed signals should give moderate-to-low rating, got {}",
            profile.rating
        );
    }

    #[test]
    fn scenario_new_contact_rapid_grooming() {
        let mut profiler = ContactProfiler::new();

        profiler.record_event(&make_event("stranger", "conv_1", EventKind::Flattery, 0));
        profiler.record_event(&make_event("stranger", "conv_1", EventKind::Flattery, 1000));

        profiler.record_event(&make_event(
            "stranger",
            "conv_1",
            EventKind::GiftOffer,
            DAY_MS,
        ));
        profiler.record_event(&make_event(
            "stranger",
            "conv_1",
            EventKind::PersonalInfoRequest,
            DAY_MS + 1000,
        ));

        profiler.record_event(&make_event(
            "stranger",
            "conv_1",
            EventKind::SecrecyRequest,
            2 * DAY_MS,
        ));
        profiler.record_event(&make_event(
            "stranger",
            "conv_1",
            EventKind::PlatformSwitch,
            2 * DAY_MS + 1000,
        ));

        profiler.record_event(&make_event(
            "stranger",
            "conv_1",
            EventKind::PhotoRequest,
            4 * DAY_MS,
        ));
        profiler.record_event(&make_event(
            "stranger",
            "conv_1",
            EventKind::MeetingRequest,
            4 * DAY_MS + 1000,
        ));

        let profile = profiler.profile("stranger").unwrap();
        assert_eq!(
            profile.circle_tier,
            CircleTier::New,
            "Should still be New (<14 days)"
        );
        assert!(
            profile.rating < 45.0,
            "Rating should drop from grooming: {}",
            profile.rating
        );
        assert!(profile.grooming_event_count >= 8);
    }

    #[test]
    fn scenario_normal_teen_drama_no_false_positive() {
        let mut profiler = ContactProfiler::new();

        for msg in 0..9 {
            profiler.record_event(&make_event(
                "classmate",
                "conv_1",
                EventKind::NormalConversation,
                msg * 1000,
            ));
        }
        profiler.record_event(&make_event(
            "classmate",
            "conv_1",
            EventKind::Insult,
            9 * 1000,
        ));

        for w in 1..5 {
            for msg in 0..10 {
                profiler.record_event(&make_event(
                    "classmate",
                    "conv_1",
                    EventKind::NormalConversation,
                    w * WEEK_MS + msg * 1000,
                ));
            }
        }
        profiler.record_event(&make_event(
            "classmate",
            "conv_1",
            EventKind::NormalConversation,
            5 * WEEK_MS + 1000,
        ));

        let profile = profiler.profile("classmate").unwrap();
        assert!(
            profile.rating > 40.0,
            "Normal teen drama should not tank rating: {}",
            profile.rating
        );
        assert!(
            profile.trend == BehavioralTrend::Stable || profile.trend == BehavioralTrend::Improving,
            "Trend should be stable/improving after reconciliation: {:?}",
            profile.trend
        );

        let signals = profiler.check_behavioral_shift("classmate");
        assert!(
            signals.is_empty(),
            "No behavioral shift signal for normal teen drama"
        );
    }

    #[test]
    fn rating_floor_after_sustained_attack() {
        let mut profiler = ContactProfiler::new();
        for i in 0..50 {
            profiler.record_event(&make_event(
                "attacker",
                "conv_1",
                EventKind::PhysicalThreat,
                i * 1000,
            ));
        }
        let profile = profiler.profile("attacker").unwrap();
        assert_eq!(profile.rating, 0.0, "Rating should floor at 0");
    }

    #[test]
    fn rating_ceiling_from_supportive() {
        let mut profiler = ContactProfiler::new();
        for i in 0..100 {
            profiler.record_event(&make_event(
                "hero",
                "conv_1",
                EventKind::DefenseOfVictim,
                i * 1000,
            ));
        }
        let profile = profiler.profile("hero").unwrap();
        assert_eq!(profile.rating, 100.0, "Rating should cap at 100");
    }

    #[test]
    fn trust_zero_floor() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "person",
            "conv_1",
            EventKind::NormalConversation,
            0,
        ));
        profiler.mark_trusted("person");

        for i in 0..50 {
            profiler.record_event(&make_event(
                "person",
                "conv_1",
                EventKind::HarmEncouragement,
                (i + 1) * 1000,
            ));
        }
        let profile = profiler.profile("person").unwrap();
        assert_eq!(profile.trust_level, 0.0, "Trust should floor at 0.0");
    }

    #[test]
    fn snapshot_at_exact_week_boundary() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "alice",
            "conv_1",
            EventKind::NormalConversation,
            0,
        ));
        profiler.record_event(&make_event(
            "alice",
            "conv_1",
            EventKind::NormalConversation,
            WEEK_MS,
        ));
        assert_eq!(profiler.profile("alice").unwrap().weekly_snapshots.len(), 1);
    }

    #[test]
    fn circle_tier_exactly_14_days() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "exact",
            "conv_1",
            EventKind::NormalConversation,
            0,
        ));
        profiler.record_event(&make_event(
            "exact",
            "conv_1",
            EventKind::NormalConversation,
            14 * DAY_MS,
        ));
        assert_ne!(
            profiler.profile("exact").unwrap().circle_tier,
            CircleTier::New,
            "At exactly 14 days should exit New tier"
        );
    }

    #[test]
    fn multiple_conversations_same_contact() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "multi",
            "conv_1",
            EventKind::NormalConversation,
            0,
        ));
        profiler.record_event(&make_event("multi", "conv_2", EventKind::Insult, 1000));
        profiler.record_event(&make_event("multi", "conv_3", EventKind::Flattery, 2000));

        let profile = profiler.profile("multi").unwrap();
        assert_eq!(profile.conversation_count, 3);
        assert_eq!(profile.total_messages, 3);
    }

    #[test]
    fn cleanup_preserves_recent_active_days() {
        let mut profiler = ContactProfiler::new();

        for day in 0..200u64 {
            profiler.record_event(&make_event(
                "longterm",
                "conv_1",
                EventKind::NormalConversation,
                day * DAY_MS,
            ));
        }

        let before = profiler.profile("longterm").unwrap().active_days.len();

        profiler.cleanup(150 * DAY_MS);

        let profile = profiler.profile("longterm").unwrap();
        assert!(
            profile.active_days.len() < before,
            "Cleanup should prune old active_days: before={before} after={}",
            profile.active_days.len()
        );
        assert!(
            !profile.active_days.is_empty(),
            "Should keep recent active_days"
        );
    }

    #[test]
    fn export_import_preserves_rating_and_snapshots() {
        let mut profiler = ContactProfiler::new();

        for w in 0..4 {
            for msg in 0..5 {
                profiler.record_event(&make_event(
                    "alice",
                    "conv_1",
                    EventKind::NormalConversation,
                    w * WEEK_MS + msg * 1000,
                ));
            }
        }
        profiler.record_event(&make_event(
            "alice",
            "conv_1",
            EventKind::Insult,
            4 * WEEK_MS,
        ));

        let state = profiler.export();
        let orig_profile = profiler.profile("alice").unwrap();
        let orig_rating = orig_profile.rating;
        let orig_snapshots = orig_profile.weekly_snapshots.len();

        let mut profiler2 = ContactProfiler::new();
        profiler2.import(state);

        let imported = profiler2.profile("alice").unwrap();
        assert_eq!(
            imported.rating, orig_rating,
            "Rating should survive export/import"
        );
        assert_eq!(
            imported.weekly_snapshots.len(),
            orig_snapshots,
            "Snapshots should survive export/import"
        );
    }

    #[test]
    fn no_behavioral_shift_for_new_contacts() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event("newbie", "conv_1", EventKind::Insult, 0));
        profiler.record_event(&make_event("newbie", "conv_1", EventKind::Insult, 1000));

        let signals = profiler.check_behavioral_shift("newbie");
        assert!(
            signals.is_empty(),
            "New contacts without 3+ snapshots should not generate shift signals"
        );
    }

    #[test]
    fn no_behavioral_shift_for_unknown_contact() {
        let profiler = ContactProfiler::new();
        let signals = profiler.check_behavioral_shift("nonexistent");
        assert!(
            signals.is_empty(),
            "Unknown contact should return empty signals"
        );
    }

    #[test]
    fn low_rating_inner_circle_alert() {
        let mut profiler = ContactProfiler::new();

        for day in 0..30u64 {
            for msg in 0..10 {
                let kind = if day < 5 {
                    EventKind::NormalConversation
                } else {
                    EventKind::PhysicalThreat
                };
                profiler.record_event(&make_event(
                    "inner_bully",
                    "conv_1",
                    kind,
                    day * DAY_MS + msg * 1000,
                ));
            }
        }

        profiler.record_event(&make_event(
            "inner_bully",
            "conv_1",
            EventKind::PhysicalThreat,
            30 * DAY_MS + 1000,
        ));
        let profile = profiler.profile("inner_bully").unwrap();
        assert_eq!(profile.circle_tier, CircleTier::Inner);

        let signals = profiler.check_behavioral_shift("inner_bully");
        let has_low_rating = signals
            .iter()
            .any(|s| s.explanation.contains("critically low rating"));
        if profile.rating < 20.0 {
            assert!(
                has_low_rating,
                "Inner circle with low rating should trigger alert"
            );
        }
    }

    #[test]
    fn graduated_trust_discount_in_risk_score() {
        let mut profiler = ContactProfiler::new();

        for i in 0..5 {
            profiler.record_event(&make_event(
                "untrusted",
                "conv_1",
                EventKind::Flattery,
                i * 1000,
            ));
            profiler.record_event(&make_event(
                "trusted",
                "conv_2",
                EventKind::Flattery,
                i * 1000,
            ));
        }
        profiler.mark_trusted("trusted");

        let untrusted_risk = profiler.profile("untrusted").unwrap().risk_score();
        let trusted_risk = profiler.profile("trusted").unwrap().risk_score();

        assert!(
            trusted_risk < untrusted_risk,
            "Trusted contact should have lower risk: trusted={trusted_risk} untrusted={untrusted_risk}"
        );
    }

    #[test]
    fn property_rating_always_in_0_100() {
        let mut profiler = ContactProfiler::new();
        let all_kinds = all_event_kinds();
        for (i, kind) in all_kinds.iter().enumerate() {
            profiler.record_event(&make_event("prop", "conv", kind.clone(), i as u64 * 1000));
            let r = profiler.profile("prop").unwrap().rating;
            assert!(
                (0.0..=100.0).contains(&r),
                "{kind:?} at step {i} produced rating {r}"
            );
        }
    }

    #[test]
    fn property_trust_always_in_0_1() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event("t", "c", EventKind::NormalConversation, 0));
        profiler.mark_trusted("t");
        let all_kinds = all_event_kinds();
        for (i, kind) in all_kinds.iter().enumerate() {
            profiler.record_event(&make_event("t", "c", kind.clone(), (i + 1) as u64 * 1000));
            let t = profiler.profile("t").unwrap().trust_level;
            assert!(
                (0.0..=1.0).contains(&t),
                "{kind:?} at step {i} produced trust {t}"
            );
        }
    }

    #[test]
    fn property_risk_score_always_in_0_1() {
        let mut profiler = ContactProfiler::new();
        let all_kinds = all_event_kinds();
        for (i, kind) in all_kinds.iter().enumerate() {
            profiler.record_event(&make_event("r", "c", kind.clone(), i as u64 * 1000));
            let r = profiler.profile("r").unwrap().risk_score();
            assert!(
                (0.0..=1.0).contains(&r),
                "{kind:?} at step {i} produced risk_score {r}"
            );
        }
    }

    #[test]
    fn property_snapshot_counters_consistent() {
        let mut profiler = ContactProfiler::new();
        let all_kinds = all_event_kinds();
        for (i, kind) in all_kinds.iter().enumerate() {
            profiler.record_event(&make_event("s", "c", kind.clone(), i as u64 * 1000));
        }
        let profile = profiler.profile("s").unwrap();
        if let Some(snap) = &profile.current_snapshot {
            let sum = snap.hostile_count + snap.supportive_count + snap.neutral_count;
            assert_eq!(
                sum, snap.total_messages,
                "hostile({}) + supportive({}) + neutral({}) != total({})",
                snap.hostile_count, snap.supportive_count, snap.neutral_count, snap.total_messages
            );
        }
    }

    #[test]
    fn property_rating_monotonic_under_pure_hostile() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event("m", "c", EventKind::NormalConversation, 0));
        let mut prev_rating = profiler.profile("m").unwrap().rating;
        let hostile_kinds = vec![
            EventKind::Insult,
            EventKind::PhysicalThreat,
            EventKind::HarmEncouragement,
            EventKind::Gaslighting,
            EventKind::EmotionalBlackmail,
            EventKind::Denigration,
            EventKind::Mockery,
            EventKind::DoxxingAttempt,
            EventKind::HateSpeech,
        ];
        for (i, kind) in hostile_kinds.iter().enumerate() {
            profiler.record_event(&make_event("m", "c", kind.clone(), (i + 1) as u64 * 1000));
            let r = profiler.profile("m").unwrap().rating;
            assert!(
                r <= prev_rating,
                "Rating increased from {prev_rating} to {r} after {kind:?}"
            );
            prev_rating = r;
        }
    }

    #[test]
    fn property_trust_monotonic_under_hostile() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event("t", "c", EventKind::NormalConversation, 0));
        profiler.mark_trusted("t");
        let mut prev_trust = 1.0;
        for i in 0..20 {
            profiler.record_event(&make_event("t", "c", EventKind::Insult, (i + 1) * 1000));
            let t = profiler.profile("t").unwrap().trust_level;
            assert!(
                t <= prev_trust,
                "Trust increased from {prev_trust} to {t} at step {i}"
            );
            prev_trust = t;
        }
    }

    #[test]
    fn property_all_event_kinds_have_valid_severity() {
        let all_kinds = all_event_kinds();
        for kind in &all_kinds {
            let s = kind.severity();
            assert!(
                (0.0..=1.0).contains(&s),
                "{kind:?} has invalid severity {s}"
            );
        }
    }

    #[test]
    fn property_hostile_events_always_negative_delta() {
        let all_kinds = all_event_kinds();
        for kind in &all_kinds {
            if kind.is_hostile() {
                assert!(
                    kind.rating_delta() < 0.0,
                    "Hostile {kind:?} has non-negative delta {}",
                    kind.rating_delta()
                );
            }
        }
    }

    #[test]
    fn property_supportive_events_always_positive_delta() {
        let all_kinds = all_event_kinds();
        for kind in &all_kinds {
            if kind.is_supportive() {
                assert!(
                    kind.rating_delta() > 0.0,
                    "Supportive {kind:?} has non-positive delta {}",
                    kind.rating_delta()
                );
            }
        }
    }

    #[test]
    fn fuzz_max_timestamp() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "x",
            "c",
            EventKind::NormalConversation,
            u64::MAX,
        ));
        let p = profiler.profile("x").unwrap();
        assert!(p.rating >= 0.0);
    }

    #[test]
    fn fuzz_zero_timestamp() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event("x", "c", EventKind::NormalConversation, 0));
        assert!(profiler.profile("x").is_some());
    }

    #[test]
    fn fuzz_empty_sender_id() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event("", "c", EventKind::NormalConversation, 1000));
        assert!(profiler.profile("").is_some());
    }

    #[test]
    fn fuzz_empty_conversation_id() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event("x", "", EventKind::NormalConversation, 1000));
        let p = profiler.profile("x").unwrap();
        assert_eq!(p.conversation_count, 1);
    }

    #[test]
    fn fuzz_unicode_sender_id() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event(
            "\u{1f9d2}\u{1f466}",
            "c",
            EventKind::Insult,
            1000,
        ));
        assert!(profiler.profile("\u{1f9d2}\u{1f466}").is_some());
    }

    #[test]
    fn fuzz_extremely_long_sender_id() {
        let mut profiler = ContactProfiler::new();
        let long_id = "a".repeat(10_000);
        profiler.record_event(&make_event(
            &long_id,
            "c",
            EventKind::NormalConversation,
            1000,
        ));
        assert!(profiler.profile(&long_id).is_some());
    }

    #[test]
    fn fuzz_timestamp_backwards() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event("x", "c", EventKind::NormalConversation, 10000));
        profiler.record_event(&make_event("x", "c", EventKind::Insult, 5000));
        let p = profiler.profile("x").unwrap();
        assert_eq!(p.last_seen_ms, 10000);
    }

    #[test]
    fn fuzz_same_timestamp_many_events() {
        let mut profiler = ContactProfiler::new();
        for _ in 0..100 {
            profiler.record_event(&make_event("x", "c", EventKind::NormalConversation, 42));
        }
        let p = profiler.profile("x").unwrap();
        assert_eq!(p.total_messages, 100);
        assert!(p.rating >= 0.0 && p.rating <= 100.0);
    }

    #[test]
    fn fuzz_rapid_trust_swing() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event("sw", "c", EventKind::NormalConversation, 0));

        for cycle in 0..5u64 {
            profiler.mark_trusted("sw");
            assert_eq!(profiler.profile("sw").unwrap().trust_level, 1.0);
            for i in 0..20 {
                profiler.record_event(&make_event(
                    "sw",
                    "c",
                    EventKind::PhysicalThreat,
                    cycle * 100000 + (i + 1) * 1000,
                ));
            }
            let t = profiler.profile("sw").unwrap().trust_level;
            assert!(
                (0.0..=1.0).contains(&t),
                "Trust out of range after cycle {cycle}: {t}"
            );
        }
    }

    #[test]
    fn fuzz_cleanup_with_zero_cutoff() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event("x", "c", EventKind::NormalConversation, 1000));
        profiler.cleanup(0);
        assert!(profiler.profile("x").is_some());
    }

    #[test]
    fn fuzz_cleanup_with_max_cutoff() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event("x", "c", EventKind::NormalConversation, 1000));
        profiler.cleanup(u64::MAX);
        assert!(profiler.profile("x").is_none());
    }

    #[test]
    fn fuzz_export_import_empty_profiler() {
        let profiler = ContactProfiler::new();
        let state = profiler.export();
        assert!(state.profiles.is_empty());
        let mut profiler2 = ContactProfiler::new();
        profiler2.import(state);
    }

    #[test]
    fn max_profile_limit_evicts_oldest_sender() {
        let mut profiler = ContactProfiler::with_max_profiles(2);
        profiler.record_event(&make_event(
            "oldest",
            "c1",
            EventKind::NormalConversation,
            1_000,
        ));
        profiler.record_event(&make_event(
            "middle",
            "c2",
            EventKind::NormalConversation,
            2_000,
        ));
        profiler.record_event(&make_event(
            "newest",
            "c3",
            EventKind::NormalConversation,
            3_000,
        ));

        assert!(profiler.profile("oldest").is_none());
        assert!(profiler.profile("middle").is_some());
        assert!(profiler.profile("newest").is_some());
    }

    #[test]
    fn max_profile_limit_prefers_keeping_higher_risk_contact() {
        let mut profiler = ContactProfiler::with_max_profiles(2);
        // Build enough grooming events to push risky_old into risk band ≥1
        // (risk_score ≥ 0.45). Each grooming event adds 0.1, capped at 0.4.
        // Five events → 0.4 grooming + severity bonus → exceeds 0.45.
        for ts in 0..5 {
            profiler.record_event(&make_event(
                "risky_old",
                "c1",
                EventKind::SecrecyRequest,
                1_000 + ts * 100,
            ));
        }
        profiler.record_event(&make_event(
            "benign_newer",
            "c2",
            EventKind::NormalConversation,
            2_000,
        ));
        profiler.record_event(&make_event(
            "incoming",
            "c3",
            EventKind::NormalConversation,
            3_000,
        ));

        assert!(profiler.profile("risky_old").is_some());
        assert!(profiler.profile("incoming").is_some());
        assert!(profiler.profile("benign_newer").is_none());
    }

    #[test]
    fn import_respects_profile_limit() {
        let mut profiler = ContactProfiler::with_max_profiles(2);
        profiler.import(ContactProfilerState {
            profiles: vec![
                ContactProfile::new("alice".into(), 1_000),
                ContactProfile::new("bob".into(), 2_000),
                ContactProfile::new("carol".into(), 3_000),
            ],
        });

        assert!(profiler.profile("alice").is_none());
        assert!(profiler.profile("bob").is_some());
        assert!(profiler.profile("carol").is_some());
    }

    #[test]
    fn fuzz_deserialize_corrupt_rating() {
        let json = r#"{"profiles":[{
            "sender_id":"x","first_seen_ms":0,"last_seen_ms":1000,"total_messages":1,
            "conversation_count":1,"conversations":["c"],"grooming_event_count":0,
            "bullying_event_count":0,"manipulation_event_count":0,"is_trusted":false,
            "severity_sum":0.0,"severity_count":0,"rating":999.0,"trust_level":5.0
        }]}"#;
        let state: ContactProfilerState = serde_json::from_str(json).unwrap();
        let mut profiler = ContactProfiler::new();
        profiler.import(state);
        let p = profiler.profile("x").unwrap();
        assert_eq!(p.rating, 999.0);
    }

    #[test]
    fn stress_1000_contacts_52_weeks() {
        let mut profiler = ContactProfiler::new();
        let week = WEEK_MS;

        for contact in 0..1000u64 {
            let sender = format!("contact_{contact}");
            for w in 0..52 {
                for msg in 0..5 {
                    let kind = if contact % 10 == 0 && w > 40 {
                        EventKind::Insult
                    } else {
                        EventKind::NormalConversation
                    };
                    profiler.record_event(&make_event(
                        &sender,
                        "conv_1",
                        kind,
                        w * week + msg * 1000 + contact,
                    ));
                }
            }
        }

        for i in 0..1000u64 {
            let sender = format!("contact_{i}");
            let p = profiler.profile(&sender).unwrap();
            assert_eq!(
                p.total_messages, 260,
                "contact_{i} should have 260 messages"
            );
            assert!((0.0..=100.0).contains(&p.rating));
            assert!((0.0..=1.0).contains(&p.trust_level));
        }

        let hostile_contact = profiler.profile("contact_0").unwrap();
        let normal_contact = profiler.profile("contact_1").unwrap();
        assert!(
            hostile_contact.rating < normal_contact.rating,
            "Hostile contact rating {} should be lower than normal {}",
            hostile_contact.rating,
            normal_contact.rating
        );

        for i in 0..1000u64 {
            let sender = format!("contact_{i}");
            let p = profiler.profile(&sender).unwrap();
            assert!(
                p.weekly_snapshots().len() <= MAX_SNAPSHOTS,
                "contact_{i} has {} snapshots, max is {MAX_SNAPSHOTS}",
                p.weekly_snapshots().len()
            );
        }
    }

    #[test]
    fn stress_sort_1000_contacts_by_risk() {
        let mut profiler = ContactProfiler::new();

        for i in 0..1000u64 {
            let sender = format!("user_{i}");
            for j in 0..(i % 10) {
                profiler.record_event(&make_event(
                    &sender,
                    "conv_1",
                    EventKind::Flattery,
                    j * 1000,
                ));
            }
            profiler.record_event(&make_event(
                &sender,
                "conv_1",
                EventKind::NormalConversation,
                10000,
            ));
        }

        let sorted = profiler.contacts_by_risk();
        assert_eq!(sorted.len(), 1000);

        for window in sorted.windows(2) {
            assert!(
                window[0].risk_score() >= window[1].risk_score(),
                "Not sorted: {} has risk {} but {} has risk {}",
                window[0].sender_id,
                window[0].risk_score(),
                window[1].sender_id,
                window[1].risk_score()
            );
        }
    }

    #[test]
    fn stress_10000_events_single_contact() {
        let mut profiler = ContactProfiler::new();

        for i in 0..10_000u64 {
            let kind = match i % 5 {
                0 => EventKind::NormalConversation,
                1 => EventKind::Insult,
                2 => EventKind::DefenseOfVictim,
                3 => EventKind::Flattery,
                _ => EventKind::NormalConversation,
            };
            profiler.record_event(&make_event("heavy", "conv_1", kind, i * 1000));
        }

        let p = profiler.profile("heavy").unwrap();
        assert_eq!(p.total_messages, 10_000);
        assert!((0.0..=100.0).contains(&p.rating));
        assert!((0.0..=1.0).contains(&p.trust_level));
        assert_eq!(p.weekly_snapshots().len(), 0, "All events within one week");
    }

    #[test]
    fn skipped_weeks_3_week_gap_then_return() {
        let mut profiler = ContactProfiler::new();

        for msg in 0..10 {
            profiler.record_event(&make_event(
                "gap",
                "conv_1",
                EventKind::NormalConversation,
                msg * 1000,
            ));
        }

        for msg in 0..10 {
            profiler.record_event(&make_event(
                "gap",
                "conv_1",
                EventKind::NormalConversation,
                4 * WEEK_MS + msg * 1000,
            ));
        }

        let p = profiler.profile("gap").unwrap();
        assert_eq!(
            p.weekly_snapshots().len(),
            1,
            "Should have 1 finalized snapshot from week 0"
        );
        assert_eq!(p.weekly_snapshots()[0].total_messages, 10);
        assert!(
            p.rating > 50.0,
            "Normal conversations should keep rating above 50: {}",
            p.rating
        );
    }

    #[test]
    fn skipped_weeks_gap_with_hostility_before_and_after() {
        let mut profiler = ContactProfiler::new();

        for w in 0..2 {
            for msg in 0..10 {
                profiler.record_event(&make_event(
                    "gap_hostile",
                    "conv_1",
                    EventKind::Insult,
                    w * WEEK_MS + msg * 1000,
                ));
            }
        }
        let rating_before_gap = profiler.profile("gap_hostile").unwrap().rating;

        for msg in 0..10 {
            profiler.record_event(&make_event(
                "gap_hostile",
                "conv_1",
                EventKind::Insult,
                6 * WEEK_MS + msg * 1000,
            ));
        }

        let p = profiler.profile("gap_hostile").unwrap();
        assert!(
            p.rating < rating_before_gap,
            "Rating should continue to decline after gap"
        );
        assert!(p.rating >= 0.0);
    }

    #[test]
    fn skipped_weeks_long_absence_8_weeks() {
        let mut profiler = ContactProfiler::new();

        for msg in 0..10 {
            profiler.record_event(&make_event(
                "absent",
                "conv_1",
                EventKind::NormalConversation,
                msg * 1000,
            ));
        }
        let friendly_rating = profiler.profile("absent").unwrap().rating;

        for msg in 0..10 {
            profiler.record_event(&make_event(
                "absent",
                "conv_1",
                EventKind::PhysicalThreat,
                9 * WEEK_MS + msg * 1000,
            ));
        }

        let p = profiler.profile("absent").unwrap();
        assert!(
            p.rating < friendly_rating,
            "Rating should drop after hostile return"
        );
        assert!(!p.weekly_snapshots().is_empty());
    }

    #[test]
    fn skipped_weeks_holiday_recovery_pattern() {
        let mut profiler = ContactProfiler::new();

        for w in 0..5 {
            for msg in 0..7 {
                profiler.record_event(&make_event(
                    "school",
                    "conv_1",
                    EventKind::NormalConversation,
                    w * WEEK_MS + msg * 1000,
                ));
            }
            for msg in 7..10 {
                profiler.record_event(&make_event(
                    "school",
                    "conv_1",
                    EventKind::Insult,
                    w * WEEK_MS + msg * 1000,
                ));
            }
        }
        let pre_holiday_rating = profiler.profile("school").unwrap().rating;

        for w in 5..13 {
            profiler.record_event(&make_event(
                "school",
                "conv_1",
                EventKind::NormalConversation,
                w * WEEK_MS + 1000,
            ));
        }
        let post_holiday_rating = profiler.profile("school").unwrap().rating;
        assert!(
            post_holiday_rating > pre_holiday_rating,
            "Rating should improve during holiday: pre={pre_holiday_rating} post={post_holiday_rating}"
        );

        for w in 13..17 {
            for msg in 0..5 {
                profiler.record_event(&make_event(
                    "school",
                    "conv_1",
                    EventKind::NormalConversation,
                    w * WEEK_MS + msg * 1000,
                ));
            }
            for msg in 5..10 {
                profiler.record_event(&make_event(
                    "school",
                    "conv_1",
                    EventKind::Insult,
                    w * WEEK_MS + msg * 1000,
                ));
            }
        }
        profiler.record_event(&make_event(
            "school",
            "conv_1",
            EventKind::Insult,
            17 * WEEK_MS + 1000,
        ));

        let final_rating = profiler.profile("school").unwrap().rating;
        assert!(
            final_rating < post_holiday_rating,
            "Rating should drop when hostility resumes: holiday={post_holiday_rating} final={final_rating}"
        );
    }

    #[test]
    fn skipped_weeks_no_snapshots_during_gap() {
        let mut profiler = ContactProfiler::new();

        profiler.record_event(&make_event("g", "c", EventKind::NormalConversation, 0));
        profiler.record_event(&make_event(
            "g",
            "c",
            EventKind::NormalConversation,
            10 * WEEK_MS,
        ));

        let p = profiler.profile("g").unwrap();
        assert_eq!(
            p.weekly_snapshots().len(),
            1,
            "Gaps should not create empty snapshots, got {}",
            p.weekly_snapshots().len()
        );
    }

    #[test]
    fn concurrent_interleaved_events_two_devices() {
        let mut profiler = ContactProfiler::new();

        for i in 0..20u64 {
            if i % 2 == 0 {
                profiler.record_event(&make_event(
                    "friend",
                    "conv_1",
                    EventKind::NormalConversation,
                    i * 500,
                ));
            } else {
                profiler.record_event(&make_event(
                    "friend",
                    "conv_2",
                    EventKind::NormalConversation,
                    i * 500,
                ));
            }
        }

        let profile = profiler.profile("friend").unwrap();
        assert_eq!(profile.total_messages, 20);
        assert_eq!(profile.conversation_count, 2);
        assert!((0.0..=100.0).contains(&profile.rating));
    }

    #[test]
    fn concurrent_export_import_mid_conversation() {
        let mut profiler = ContactProfiler::new();

        for i in 0..5 {
            profiler.record_event(&make_event(
                "alice",
                "conv_1",
                EventKind::NormalConversation,
                i * 1000,
            ));
        }
        let mid_rating = profiler.profile("alice").unwrap().rating;

        let checkpoint = profiler.export();

        for i in 5..10 {
            profiler.record_event(&make_event("alice", "conv_1", EventKind::Insult, i * 1000));
        }
        let post_hostile_rating = profiler.profile("alice").unwrap().rating;
        assert!(post_hostile_rating < mid_rating);

        let mut device2 = ContactProfiler::new();
        device2.import(checkpoint);
        let device2_rating = device2.profile("alice").unwrap().rating;
        assert_eq!(
            device2_rating, mid_rating,
            "Device 2 should have checkpoint rating"
        );

        for i in 10..15 {
            device2.record_event(&make_event(
                "alice",
                "conv_1",
                EventKind::NormalConversation,
                i * 1000,
            ));
        }
        let device2_final = device2.profile("alice").unwrap().rating;
        assert!(
            device2_final > device2_rating,
            "Device 2 should improve with normal msgs"
        );
    }

    #[test]
    fn concurrent_import_overwrites_stale_profile() {
        let mut device_a = ContactProfiler::new();
        device_a.record_event(&make_event(
            "bob",
            "conv_1",
            EventKind::NormalConversation,
            0,
        ));

        let mut server = ContactProfiler::new();
        for i in 0..20 {
            server.record_event(&make_event(
                "bob",
                "conv_1",
                EventKind::NormalConversation,
                i * 1000,
            ));
        }
        let server_state = server.export();

        device_a.import(server_state);
        let profile = device_a.profile("bob").unwrap();
        assert_eq!(
            profile.total_messages, 20,
            "Import should overwrite stale data"
        );
    }

    #[test]
    fn concurrent_multiple_contacts_independent() {
        let mut profiler = ContactProfiler::new();

        for i in 0..10 {
            profiler.record_event(&make_event("alice", "conv_1", EventKind::Insult, i * 1000));
        }

        for i in 0..10 {
            profiler.record_event(&make_event(
                "bob",
                "conv_2",
                EventKind::DefenseOfVictim,
                i * 1000,
            ));
        }

        for i in 0..10 {
            profiler.record_event(&make_event(
                "charlie",
                "conv_3",
                EventKind::Flattery,
                i * 1000,
            ));
        }

        let alice = profiler.profile("alice").unwrap();
        let bob = profiler.profile("bob").unwrap();
        let charlie = profiler.profile("charlie").unwrap();

        assert!(
            alice.rating < 50.0,
            "Alice should have low rating: {}",
            alice.rating
        );
        assert!(
            bob.rating > 50.0,
            "Bob should have high rating: {}",
            bob.rating
        );
        assert!(
            charlie.rating < 50.0,
            "Charlie (grooming) should have slightly low rating: {}",
            charlie.rating
        );

        assert_eq!(alice.bullying_event_count, 10);
        assert_eq!(bob.bullying_event_count, 0);
        assert_eq!(charlie.grooming_event_count, 10);
    }

    #[test]
    fn concurrent_export_import_preserves_all_contacts() {
        let mut profiler = ContactProfiler::new();

        for i in 0..50u64 {
            let sender = format!("user_{i}");
            for j in 0..5 {
                profiler.record_event(&make_event(
                    &sender,
                    "conv_1",
                    EventKind::NormalConversation,
                    j * 1000,
                ));
            }
        }

        let state = profiler.export();
        assert_eq!(state.profiles.len(), 50);

        let mut profiler2 = ContactProfiler::new();
        profiler2.import(state);

        for i in 0..50u64 {
            let sender = format!("user_{i}");
            let p = profiler2.profile(&sender);
            assert!(p.is_some(), "user_{i} should exist after import");
            assert_eq!(p.unwrap().total_messages, 5);
        }
    }

    #[test]
    fn concurrent_cleanup_during_active_use() {
        let mut profiler = ContactProfiler::new();

        profiler.record_event(&make_event(
            "old_user",
            "conv_1",
            EventKind::NormalConversation,
            1000,
        ));

        let active_ts = 100 * DAY_MS;
        for i in 0..10 {
            profiler.record_event(&make_event(
                "active_user",
                "conv_1",
                EventKind::NormalConversation,
                active_ts + i * 1000,
            ));
        }

        profiler.cleanup(50 * DAY_MS);
        assert!(
            profiler.profile("old_user").is_none(),
            "Old user should be removed"
        );
        assert!(
            profiler.profile("active_user").is_some(),
            "Active user should survive"
        );

        profiler.record_event(&make_event(
            "active_user",
            "conv_1",
            EventKind::NormalConversation,
            active_ts + 20000,
        ));
        profiler.record_event(&make_event(
            "new_user",
            "conv_1",
            EventKind::Flattery,
            active_ts + 30000,
        ));

        assert_eq!(profiler.profile("active_user").unwrap().total_messages, 11);
        assert!(
            profiler.profile("new_user").is_some(),
            "New user after cleanup should work"
        );
    }

    #[test]
    fn concurrent_import_then_mark_trusted() {
        let mut profiler1 = ContactProfiler::new();
        for i in 0..5 {
            profiler1.record_event(&make_event(
                "uncle",
                "conv_1",
                EventKind::NormalConversation,
                i * 1000,
            ));
        }
        let state = profiler1.export();

        let mut profiler2 = ContactProfiler::new();
        profiler2.import(state);
        profiler2.mark_trusted("uncle");

        let profile = profiler2.profile("uncle").unwrap();
        assert_eq!(profile.trust_level, 1.0);
        assert!(profile.is_trusted);

        for i in 0..5 {
            profiler2.record_event(&make_event(
                "uncle",
                "conv_1",
                EventKind::Insult,
                10000 + i * 1000,
            ));
        }
        let profile = profiler2.profile("uncle").unwrap();
        assert!(
            profile.trust_level < 1.0,
            "Trust should decay after import+mark+hostile"
        );
    }

    #[test]
    fn concurrent_double_import_last_wins() {
        let mut profiler = ContactProfiler::new();

        let mut p1 = ContactProfiler::new();
        for i in 0..5 {
            p1.record_event(&make_event(
                "alice",
                "conv_1",
                EventKind::NormalConversation,
                i * 1000,
            ));
        }
        let state1 = p1.export();

        let mut p2 = ContactProfiler::new();
        for i in 0..5 {
            p2.record_event(&make_event("alice", "conv_1", EventKind::Insult, i * 1000));
        }
        let state2 = p2.export();

        let rating1 = p1.profile("alice").unwrap().rating;
        let rating2 = p2.profile("alice").unwrap().rating;
        assert!(
            rating1 > rating2,
            "State1 should have higher rating than state2"
        );

        profiler.import(state1);
        assert_eq!(profiler.profile("alice").unwrap().rating, rating1);
        profiler.import(state2);
        assert_eq!(
            profiler.profile("alice").unwrap().rating,
            rating2,
            "Second import should overwrite first"
        );
    }

    #[test]
    fn concurrent_export_import_with_behavioral_snapshots() {
        let mut profiler = ContactProfiler::new();

        for w in 0..3 {
            for msg in 0..10 {
                profiler.record_event(&make_event(
                    "contact",
                    "conv_1",
                    EventKind::NormalConversation,
                    w * WEEK_MS + msg * 1000,
                ));
            }
        }
        for w in 3..6 {
            for msg in 0..6 {
                profiler.record_event(&make_event(
                    "contact",
                    "conv_1",
                    EventKind::NormalConversation,
                    w * WEEK_MS + msg * 1000,
                ));
            }
            for msg in 6..10 {
                profiler.record_event(&make_event(
                    "contact",
                    "conv_1",
                    EventKind::Insult,
                    w * WEEK_MS + msg * 1000,
                ));
            }
        }
        profiler.record_event(&make_event(
            "contact",
            "conv_1",
            EventKind::Insult,
            6 * WEEK_MS + 1000,
        ));

        let orig = profiler.profile("contact").unwrap();
        let orig_snapshots = orig.weekly_snapshots().len();
        let orig_trend = orig.trend;
        let orig_rating = orig.rating;

        let state = profiler.export();
        let mut profiler2 = ContactProfiler::new();
        profiler2.import(state);

        let imported = profiler2.profile("contact").unwrap();
        assert_eq!(imported.weekly_snapshots().len(), orig_snapshots);
        assert_eq!(imported.trend, orig_trend);
        assert_eq!(imported.rating, orig_rating);

        let signals = profiler2.check_behavioral_shift("contact");
        let orig_signals = profiler.check_behavioral_shift("contact");
        assert_eq!(
            signals.len(),
            orig_signals.len(),
            "Behavioral shift signals should match after import"
        );
    }

    #[test]
    fn merge_import_preserves_local_profile() {
        let mut profiler_a = ContactProfiler::new();
        profiler_a.record_event(&make_event("alice", "conv_1", EventKind::Insult, 1000));
        profiler_a.record_event(&make_event("alice", "conv_1", EventKind::Insult, 2000));

        let mut profiler_b = ContactProfiler::new();
        profiler_b.record_event(&make_event(
            "alice",
            "conv_2",
            EventKind::NormalConversation,
            3000,
        ));

        let state_b = profiler_b.export();
        profiler_a.merge_import(state_b);

        let profile = profiler_a.profile("alice").unwrap();
        assert!(
            profile.bullying_event_count >= 2,
            "Should preserve higher bullying count from A"
        );
        assert!(
            profile.conversation_count >= 2,
            "Should have conversations from both A and B"
        );
    }

    #[test]
    fn merge_import_takes_most_cautious_trust() {
        let mut profiler_a = ContactProfiler::new();
        profiler_a.record_event(&make_event(
            "alice",
            "conv_1",
            EventKind::NormalConversation,
            1000,
        ));
        profiler_a.mark_trusted("alice");

        let mut profiler_b = ContactProfiler::new();
        profiler_b.record_event(&make_event("alice", "conv_1", EventKind::Insult, 2000));
        let state_b = profiler_b.export();
        profiler_a.merge_import(state_b);

        let profile = profiler_a.profile("alice").unwrap();
        assert!(
            !profile.is_trusted,
            "Should take most cautious trust: false"
        );
    }

    #[test]
    fn merge_import_inserts_new_profiles() {
        let mut profiler_a = ContactProfiler::new();
        profiler_a.record_event(&make_event(
            "alice",
            "conv_1",
            EventKind::NormalConversation,
            1000,
        ));

        let mut profiler_b = ContactProfiler::new();
        profiler_b.record_event(&make_event(
            "bob",
            "conv_2",
            EventKind::NormalConversation,
            2000,
        ));

        let state_b = profiler_b.export();
        profiler_a.merge_import(state_b);

        assert!(profiler_a.profile("alice").is_some());
        assert!(profiler_a.profile("bob").is_some());
    }

    #[test]
    fn merge_import_takes_earliest_first_seen() {
        let mut profiler_a = ContactProfiler::new();
        profiler_a.record_event(&make_event(
            "alice",
            "conv_1",
            EventKind::NormalConversation,
            5000,
        ));

        let mut profiler_b = ContactProfiler::new();
        profiler_b.record_event(&make_event(
            "alice",
            "conv_1",
            EventKind::NormalConversation,
            1000,
        ));

        let state_b = profiler_b.export();
        profiler_a.merge_import(state_b);

        let profile = profiler_a.profile("alice").unwrap();
        assert_eq!(
            profile.first_seen_ms, 1000,
            "Should take earliest first_seen"
        );
    }

    #[test]
    fn merge_import_preserves_fingerprint_frequency() {
        let mut profiler_a = ContactProfiler::new();
        let mut event_a = make_event("alice", "conv_1", EventKind::PropagandaNarrative, 1_000);
        event_a.subtype = Some("war_denial".to_string());
        event_a.content_hash = Some(777);
        profiler_a.record_event(&event_a);

        let mut profiler_b = ContactProfiler::new();
        for i in 0..5 {
            let mut event_b = make_event(
                "alice",
                "conv_1",
                EventKind::PropagandaNarrative,
                2_000 + i * 1_000,
            );
            event_b.subtype = Some("war_denial".to_string());
            event_b.content_hash = Some(777);
            profiler_b.record_event(&event_b);
        }

        profiler_a.merge_import(profiler_b.export());

        let profile = profiler_a.profile("alice").unwrap();
        let count = profile
            .message_fingerprints
            .iter()
            .filter(|&&fingerprint| fingerprint == 777)
            .count();
        assert!(count >= 5, "Expected repeated fingerprints to be preserved");
    }

    #[test]
    fn merge_import_same_state_does_not_inflate_fingerprints() {
        let mut source = ContactProfiler::new();
        for i in 0..4 {
            let mut event = make_event(
                "alice",
                "conv_1",
                EventKind::PropagandaNarrative,
                1_000 + i * 1_000,
            );
            event.subtype = Some("war_denial".to_string());
            event.content_hash = Some(404);
            source.record_event(&event);
        }

        let state = source.export();
        let mut local = ContactProfiler::new();
        local.merge_import(state.clone());
        local.merge_import(state);

        let profile = local.profile("alice").unwrap();
        let count = profile
            .message_fingerprints
            .iter()
            .filter(|&&fingerprint| fingerprint == 404)
            .count();
        assert_eq!(
            count, 4,
            "Repeated merge of same state should not inflate counts"
        );
    }

    #[test]
    fn merge_import_recomputes_narrative_diversity_from_union() {
        let mut profiler_a = ContactProfiler::new();
        let mut a = make_event("alice", "conv_1", EventKind::PropagandaNarrative, 1_000);
        a.subtype = Some("war_denial".to_string());
        profiler_a.record_event(&a);

        let mut profiler_b = ContactProfiler::new();
        let mut b = make_event("alice", "conv_1", EventKind::PropagandaNarrative, 2_000);
        b.subtype = Some("capitulation".to_string());
        profiler_b.record_event(&b);

        profiler_a.merge_import(profiler_b.export());

        let profile = profiler_a.profile("alice").unwrap();
        assert_eq!(
            profile.narrative_diversity, 2,
            "Narrative diversity should reflect merged unique narrative ids"
        );
    }

    #[test]
    fn merge_import_same_state_does_not_inflate_weekly_counts() {
        let mut source = ContactProfiler::new();
        for i in 0..4 {
            let mut event = make_event(
                "alice",
                "conv_1",
                EventKind::PropagandaNarrative,
                1_000 + i * 1_000,
            );
            event.subtype = Some("war_denial".to_string());
            source.record_event(&event);
        }

        let state = source.export();
        let mut local = ContactProfiler::new();
        local.merge_import(state.clone());
        local.merge_import(state);

        let profile = local.profile("alice").unwrap();
        assert_eq!(profile.weekly_propaganda_counts.len(), 1);
        assert_eq!(
            profile.weekly_propaganda_counts[0].1, 4,
            "Repeated merge of same state should not inflate per-week counts"
        );
    }

    #[test]
    fn merge_import_is_idempotent_for_same_state() {
        let mut source = ContactProfiler::new();
        for i in 0..6 {
            let mut event = make_event(
                "alice",
                "conv_1",
                EventKind::PropagandaNarrative,
                1_000 + i * 1_000,
            );
            event.subtype = Some("war_denial".to_string());
            event.content_hash = Some(901);
            source.record_event(&event);
        }
        for i in 0..3 {
            source.record_event(&make_event(
                "alice",
                "conv_1",
                EventKind::NormalConversation,
                20_000 + i * 1_000,
            ));
        }

        let state = source.export();
        let mut local = ContactProfiler::new();
        local.merge_import(state.clone());
        let before = local.profile("alice").unwrap().clone();
        local.merge_import(state);
        let after = local.profile("alice").unwrap().clone();

        assert_eq!(before.propaganda_event_count, after.propaganda_event_count);
        assert_eq!(
            before.propaganda_source_count,
            after.propaganda_source_count
        );
        assert_eq!(before.narrative_hits, after.narrative_hits);
        assert_eq!(before.narrative_diversity, after.narrative_diversity);
        assert_eq!(
            before.weekly_propaganda_counts,
            after.weekly_propaganda_counts
        );
        assert_eq!(before.message_fingerprints, after.message_fingerprints);
        assert!(
            (before.propaganda_score - after.propaganda_score).abs() < 1e-6,
            "Idempotent merge should keep propaganda_score stable"
        );
    }

    #[test]
    fn merge_import_preserves_most_cautious_average_severity() {
        let mut local = ContactProfiler::new();
        local.record_event(&make_event(
            "alice",
            "conv_1",
            EventKind::NormalConversation,
            1_000,
        ));
        {
            let profile = local.profiles.get_mut("alice").unwrap();
            profile.severity_sum = 2.0;
            profile.severity_count = 10;
        }

        let mut incoming = ContactProfiler::new();
        incoming.record_event(&make_event(
            "alice",
            "conv_2",
            EventKind::NormalConversation,
            2_000,
        ));
        {
            let profile = incoming.profiles.get_mut("alice").unwrap();
            profile.severity_sum = 8.0;
            profile.severity_count = 4;
        }

        local.merge_import(incoming.export());
        let profile = local.profile("alice").unwrap();
        assert_eq!(profile.severity_count, 10);
        assert!((profile.average_severity() - 2.0).abs() < 1e-6);
    }

    #[test]
    fn merge_import_never_decreases_cautious_counters() {
        let mut local = ContactProfiler::new();
        let mut local_event = make_event("alice", "conv_1", EventKind::PropagandaNarrative, 1_000);
        local_event.subtype = Some("war_denial".to_string());
        local_event.content_hash = Some(777);
        local.record_event(&local_event);
        local.record_event(&make_event(
            "alice",
            "conv_1",
            EventKind::SuspiciousSource,
            2_000,
        ));

        let mut incoming_profiler = ContactProfiler::new();
        for i in 0..4 {
            let mut event = make_event(
                "alice",
                "conv_2",
                EventKind::PropagandaNarrative,
                3_000 + i * 1_000,
            );
            event.subtype = Some("capitulation".to_string());
            event.content_hash = Some(888);
            incoming_profiler.record_event(&event);
        }

        let before = local.profile("alice").unwrap().clone();
        local.merge_import(incoming_profiler.export());
        let after = local.profile("alice").unwrap().clone();

        assert!(after.propaganda_event_count >= before.propaganda_event_count);
        assert!(after.propaganda_source_count >= before.propaganda_source_count);
        assert!(after.narrative_diversity >= before.narrative_diversity);
        assert!(after.propaganda_conversations.len() >= before.propaganda_conversations.len());
        assert!(after.last_seen_ms >= before.last_seen_ms);
        assert!(after.first_seen_ms <= before.first_seen_ms);
    }
}
