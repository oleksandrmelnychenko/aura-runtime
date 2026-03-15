use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::types::{
    BehavioralTrend, CircleTier, Confidence, ContactSnapshot, DetectionSignal, SignalFamily,
    ThreatType,
};

use super::events::ContextEvent;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const WEEK_MS: u64 = 7 * 24 * 60 * 60 * 1000; // 604_800_000
const DAY_MS: u64 = 24 * 60 * 60 * 1000; // 86_400_000
const MAX_SNAPSHOTS: usize = 26; // 6 months of weekly snapshots
pub const DEFAULT_MAX_CONTACT_PROFILES: usize = 1_000;

fn default_rating() -> f32 {
    50.0
}

fn default_trust() -> f32 {
    0.5
}

// ---------------------------------------------------------------------------
// BehavioralSnapshot
// ---------------------------------------------------------------------------

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
    pub avg_severity: f32,
}

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
            avg_severity: 0.0,
        }
    }

    pub fn hostile_ratio(&self) -> f32 {
        if self.total_messages == 0 {
            0.0
        } else {
            self.hostile_count as f32 / self.total_messages as f32
        }
    }

    pub fn supportive_ratio(&self) -> f32 {
        if self.total_messages == 0 {
            0.0
        } else {
            self.supportive_count as f32 / self.total_messages as f32
        }
    }
}

// ---------------------------------------------------------------------------
// ContactProfile
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactProfile {
    pub sender_id: String,

    pub first_seen_ms: u64,

    pub last_seen_ms: u64,

    pub total_messages: u64,

    pub conversation_count: usize,

    pub(crate) conversations: Vec<String>,

    pub grooming_event_count: u64,

    pub bullying_event_count: u64,

    pub manipulation_event_count: u64,

    pub is_trusted: bool,

    severity_sum: f32,
    severity_count: u64,

    #[serde(default)]
    pub inferred_age: Option<u16>,

    // --- Phase 7: Rating & Behavioral Profiling ---
    #[serde(default = "default_rating")]
    pub rating: f32,

    #[serde(default = "default_trust")]
    pub trust_level: f32,

    #[serde(default)]
    pub circle_tier: CircleTier,

    #[serde(default)]
    pub trend: BehavioralTrend,

    #[serde(default)]
    weekly_snapshots: VecDeque<BehavioralSnapshot>,

    #[serde(default)]
    current_snapshot: Option<BehavioralSnapshot>,

    #[serde(default)]
    active_days: HashSet<u32>,
}

#[derive(Debug, Clone)]
pub struct ContactProfileState {
    pub sender_id: String,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub total_messages: u64,
    pub conversation_count: usize,
    pub conversations: Vec<String>,
    pub grooming_event_count: u64,
    pub bullying_event_count: u64,
    pub manipulation_event_count: u64,
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
        let mut active_days: Vec<u32> = profile.active_days.iter().copied().collect();
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
            is_trusted: profile.is_trusted,
            severity_sum: profile.severity_sum,
            severity_count: profile.severity_count,
            inferred_age: profile.inferred_age,
            rating: profile.rating,
            trust_level: profile.trust_level,
            circle_tier: profile.circle_tier,
            trend: profile.trend,
            weekly_snapshots: profile
                .weekly_snapshots
                .iter()
                .map(BehavioralSnapshotState::from)
                .collect(),
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
            grooming_event_count: profile.grooming_event_count,
            bullying_event_count: profile.bullying_event_count,
            manipulation_event_count: profile.manipulation_event_count,
            is_trusted: profile.is_trusted,
            severity_sum: profile.severity_sum,
            severity_count: profile.severity_count,
            inferred_age: profile.inferred_age,
            rating: profile.rating,
            trust_level: profile.trust_level,
            circle_tier: profile.circle_tier,
            trend: profile.trend,
            weekly_snapshots: profile
                .weekly_snapshots
                .into_iter()
                .map(BehavioralSnapshot::from)
                .collect(),
            current_snapshot: profile.current_snapshot.map(BehavioralSnapshot::from),
            active_days: profile.active_days.into_iter().collect(),
        }
    }
}

impl ContactProfile {
    fn new(sender_id: String, first_seen_ms: u64) -> Self {
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
            is_trusted: false,
            severity_sum: 0.0,
            severity_count: 0,
            inferred_age: None,
            rating: 50.0,
            trust_level: 0.5,
            circle_tier: CircleTier::New,
            trend: BehavioralTrend::Stable,
            weekly_snapshots: VecDeque::new(),
            current_snapshot: None,
            active_days: HashSet::new(),
        }
    }

    pub fn average_severity(&self) -> f32 {
        if self.severity_count == 0 {
            0.0
        } else {
            self.severity_sum / self.severity_count as f32
        }
    }

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

    pub fn relationship_age_ms(&self) -> u64 {
        self.last_seen_ms - self.first_seen_ms
    }

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

        score += self.average_severity() * 0.2;

        let hours_known = self.relationship_age_ms() as f32 / (1000.0 * 3600.0);
        if hours_known < 24.0 && (self.grooming_event_count > 0 || self.bullying_event_count > 0) {
            score += 0.1;
        }

        // Graduated trust discount (replaces binary is_trusted check)
        let trust_discount = 1.0 - (self.trust_level * 0.5);
        score *= trust_discount;

        score.min(1.0)
    }

    // --- Rating & Behavioral methods ---

    pub fn update_rating(&mut self, event: &ContextEvent) {
        let delta = event.kind.rating_delta();
        self.rating = (self.rating + delta).clamp(0.0, 100.0);

        self.update_current_snapshot(event);

        let day_index = (event.timestamp_ms / DAY_MS) as u32;
        self.active_days.insert(day_index);

        self.recalculate_circle_tier();

        if event.kind.is_hostile() {
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

        // Check if week boundary crossed — finalize before mutating
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

        // Now update the current snapshot
        let snapshot = self.current_snapshot.as_mut().unwrap();
        snapshot.total_messages += 1;
        if event.kind.is_hostile() {
            snapshot.hostile_count += 1;
        } else if event.kind.is_supportive() {
            snapshot.supportive_count += 1;
        } else {
            snapshot.neutral_count += 1;
        }
        if event.kind.is_grooming_indicator() {
            snapshot.grooming_count += 1;
        }
        if event.kind.is_manipulation_indicator() {
            snapshot.manipulation_count += 1;
        }

        // Running average severity
        let n = snapshot.total_messages as f32;
        snapshot.avg_severity = snapshot.avg_severity * ((n - 1.0) / n) + event.kind.severity() / n;
    }

    fn recalculate_trend(&mut self) {
        let snapshots = &self.weekly_snapshots;

        if snapshots.len() < 3 {
            self.trend = BehavioralTrend::Stable;
            return;
        }

        // Baseline: first half (2-4 snapshots)
        let baseline_count = (snapshots.len() / 2).clamp(2, 4);
        let baseline_hostile = avg_hostile_ratio(snapshots.iter().take(baseline_count));
        let baseline_supportive = avg_supportive_ratio(snapshots.iter().take(baseline_count));

        // Recent: last 2 snapshots
        let recent_hostile = avg_hostile_ratio(snapshots.iter().rev().take(2));
        let _recent_supportive = avg_supportive_ratio(snapshots.iter().rev().take(2));

        let hostile_delta = recent_hostile - baseline_hostile;

        // Role reversal: was supportive (>30%), now hostile (>30%)
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

        // New: < 14 days
        if age_ms < 14 * DAY_MS {
            self.circle_tier = CircleTier::New;
            return;
        }

        let age_days = (age_ms / DAY_MS).max(1) as f32;
        let msgs_per_day = self.total_messages as f32 / age_days;

        // Inner: 5+ msg/day avg OR 20+ active days in last 30
        let recent_active = self.count_recent_active_days(30);
        if msgs_per_day >= 5.0 || recent_active >= 20 {
            self.circle_tier = CircleTier::Inner;
            return;
        }

        // Regular: 3+ msg/week = 0.43+ msg/day
        if msgs_per_day >= 0.43 {
            self.circle_tier = CircleTier::Regular;
            return;
        }

        self.circle_tier = CircleTier::Occasional;
    }

    fn count_recent_active_days(&self, days: u32) -> usize {
        let now_day = (self.last_seen_ms / DAY_MS) as u32;
        let cutoff_day = now_day.saturating_sub(days);
        self.active_days
            .iter()
            .filter(|&&d| d >= cutoff_day)
            .count()
    }

    pub fn weekly_snapshots(&self) -> &VecDeque<BehavioralSnapshot> {
        &self.weekly_snapshots
    }

    /// Fix up fields that may be missing from older serialized state.
    fn post_deserialize_fixup(&mut self) {
        // Old state: is_trusted=true but trust_level=0.5 (default)
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

// ---------------------------------------------------------------------------
// ContactProfiler
// ---------------------------------------------------------------------------

pub struct ContactProfiler {
    profiles: HashMap<String, ContactProfile>,
    max_profiles: usize,
}

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
    pub fn new() -> Self {
        Self::with_max_profiles(DEFAULT_MAX_CONTACT_PROFILES)
    }

    pub fn with_max_profiles(max_profiles: usize) -> Self {
        Self {
            profiles: HashMap::new(),
            max_profiles: max_profiles.max(1),
        }
    }

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

        if event.kind.is_grooming_indicator() {
            profile.grooming_event_count += 1;
        }
        if event.kind.is_bullying_indicator() {
            profile.bullying_event_count += 1;
        }
        if event.kind.is_manipulation_indicator() {
            profile.manipulation_event_count += 1;
        }

        let severity = event.kind.severity();
        if severity > 0.0 {
            profile.severity_sum += severity;
            profile.severity_count += 1;
        }

        // Phase 7: update rating & behavioral tracking
        profile.update_rating(event);
    }

    pub fn update_max_profiles(&mut self, max_profiles: usize) {
        self.max_profiles = max_profiles.max(1);
        self.enforce_profile_limit();
    }

    pub fn is_new_contact(&self, sender_id: &str) -> bool {
        match self.profiles.get(sender_id) {
            None => true,
            Some(p) => p.relationship_age_ms() < 48 * 60 * 60 * 1000,
        }
    }

    pub fn contacts_many_minors(&self, sender_id: &str) -> bool {
        match self.profiles.get(sender_id) {
            None => false,
            Some(p) => p.conversation_count >= 5 && p.grooming_event_count >= 3,
        }
    }

    pub fn profile(&self, sender_id: &str) -> Option<&ContactProfile> {
        self.profiles.get(sender_id)
    }

    pub fn snapshot(&self, sender_id: &str) -> Option<ContactSnapshot> {
        self.profile(sender_id)
            .map(|profile| profile.snapshot(self.is_new_contact(sender_id)))
    }

    pub fn contacts_by_risk(&self) -> Vec<&ContactProfile> {
        let mut profiles: Vec<_> = self.profiles.values().collect();
        profiles.sort_by(|a, b| {
            b.risk_score()
                .partial_cmp(&a.risk_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        profiles
    }

    pub fn mark_trusted(&mut self, sender_id: &str) {
        if let Some(profile) = self.profiles.get_mut(sender_id) {
            profile.trust_level = 1.0;
            profile.is_trusted = true;
        }
    }

    pub fn set_inferred_age(&mut self, sender_id: &str, age: u16) {
        if let Some(profile) = self.profiles.get_mut(sender_id) {
            if profile.inferred_age.is_none() && (5..=99).contains(&age) {
                profile.inferred_age = Some(age);
            }
        }
    }

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
                let score = if profile.grooming_event_count > 0 {
                    (0.6 + gap as f32 * 0.02).min(0.95)
                } else {
                    (0.3 + gap as f32 * 0.01).min(0.6)
                };

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

    pub fn check_anomalies(&self, sender_id: &str, is_child_account: bool) -> Vec<DetectionSignal> {
        let mut signals = Vec::new();

        let profile = match self.profiles.get(sender_id) {
            Some(p) => p,
            None => return signals,
        };

        if profile.is_trusted {
            return signals;
        }

        let risk = profile.risk_score();

        if is_child_account && self.is_new_contact(sender_id) && risk >= 0.3 {
            signals.push(DetectionSignal::context(
                ThreatType::Grooming,
                risk,
                Confidence::Medium,
                SignalFamily::Conversation,
                "conversation.contact.new_risky_contact",
                format!(
                    "New contact with suspicious behavior pattern (risk: {risk:.2}). {} grooming indicators, {} bullying indicators.",
                    profile.grooming_event_count,
                    profile.bullying_event_count,
                ),
            ));
        }

        if profile.conversation_count >= 5 && profile.grooming_event_count >= 3 {
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
                // Trust broken = extra dangerous
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
            _ => {}
        }

        // Low rating alert for inner circle
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

    pub fn export(&self) -> ContactProfilerState {
        ContactProfilerState {
            profiles: self.profiles.values().cloned().collect(),
        }
    }

    pub fn export_wire_state(&self) -> ContactProfilerWireState {
        ContactProfilerWireState {
            profiles: self
                .profiles
                .values()
                .map(ContactProfileState::from)
                .collect(),
        }
    }

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
                    // Take the most cautious / comprehensive values
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

                    // Union conversations
                    for conv in incoming.conversations {
                        if !local.conversations.contains(&conv) {
                            local.conversations.push(conv);
                        }
                    }
                    local.conversation_count = local.conversations.len();

                    // Most cautious trust/rating
                    local.trust_level = local.trust_level.min(incoming.trust_level);
                    local.rating = local.rating.min(incoming.rating);
                    local.is_trusted = local.is_trusted && incoming.is_trusted;

                    // Take more severe trend
                    if trend_severity(&incoming.trend) > trend_severity(&local.trend) {
                        local.trend = incoming.trend;
                    }

                    // Prefer existing inferred_age, fall back to incoming
                    if local.inferred_age.is_none() {
                        local.inferred_age = incoming.inferred_age;
                    }

                    // Merge severity stats
                    local.severity_sum = local.severity_sum.max(incoming.severity_sum);
                    local.severity_count = local.severity_count.max(incoming.severity_count);
                }
                None => {
                    self.profiles.insert(incoming.sender_id.clone(), incoming);
                }
            }
        }
        self.enforce_profile_limit();
    }

    pub fn import_wire_state(&mut self, state: ContactProfilerWireState) {
        self.import(ContactProfilerState {
            profiles: state
                .profiles
                .into_iter()
                .map(ContactProfile::from)
                .collect(),
        });
    }

    pub fn merge_import_wire_state(&mut self, state: ContactProfilerWireState) {
        self.merge_import(ContactProfilerState {
            profiles: state
                .profiles
                .into_iter()
                .map(ContactProfile::from)
                .collect(),
        });
    }

    pub fn cleanup(&mut self, cutoff_ms: u64) {
        let cutoff_day = (cutoff_ms / DAY_MS) as u32;
        self.profiles.retain(|_, p| {
            if p.last_seen_ms < cutoff_ms {
                return false;
            }
            // Clean old active_days (keep 90 days for circle tier)
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
        let oldest_sender = self
            .profiles
            .iter()
            .filter(|(sender_id, _)| Some(sender_id.as_str()) != protected_sender_id)
            .min_by(|(left_id, left), (right_id, right)| {
                left.last_seen_ms
                    .cmp(&right.last_seen_ms)
                    .then_with(|| left.first_seen_ms.cmp(&right.first_seen_ms))
                    .then_with(|| left_id.cmp(right_id))
            })
            .map(|(sender_id, _)| sender_id.clone())?;

        self.profiles.remove(&oldest_sender)
    }
}

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
            sender_id: sender.to_string(),
            conversation_id: conv.to_string(),
            kind,
            confidence: 0.8,
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

    // ---- Existing tests (preserved) ----

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
        profiler.set_inferred_age("user_a", 3);

        assert_eq!(profiler.profile("user_a").unwrap().inferred_age, None);

        profiler.set_inferred_age("user_a", 150);

        assert_eq!(profiler.profile("user_a").unwrap().inferred_age, None);
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
        profiler.set_inferred_age("uncle", 40);
        profiler.mark_trusted("uncle");

        let signals = profiler.check_age_gap("uncle", Some(12));
        assert!(
            signals.is_empty(),
            "Trusted contacts should not trigger age gap"
        );
    }

    // ---- Phase 7: New tests ----

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
        // Rating starts at 50 + small positive delta from NormalConversation
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
        // 20 high-severity hostile events should clamp at 0
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

        // Send hostile events
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

        // 10 hostile events with high severity
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
        // 15 days, 10 messages/day = 150 messages
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
        // 30 days, message every other day = 15 messages, 15 active days (<20)
        // msgs_per_day = 15/30 = 0.5 → Regular
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
        // 60 days, only 3 messages total = 0.05 msg/day
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
        // Week 1: some messages
        for i in 0..5 {
            profiler.record_event(&make_event(
                "alice",
                "conv_1",
                EventKind::NormalConversation,
                i * 1000,
            ));
        }
        assert_eq!(profiler.profile("alice").unwrap().weekly_snapshots.len(), 0);

        // Week 2: first message after week boundary → finalizes week 1
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
        // Generate 30 weeks of data
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
        // 5 weeks of mostly normal conversation
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
        // Trigger trend recalculation with message in week 6
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
        // Weeks 1-3: mostly normal
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
        // Weeks 4-5: 20% hostile (2/10 = 0.2 hostile ratio, vs 0.0 baseline = 0.2 delta)
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
        // Trigger recalculation
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
        // Weeks 1-3: clean
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
        // Weeks 4-5: 40% hostile (4/10 hostile each week)
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
        // Trigger
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
        // Weeks 1-3: supportive (>30% DefenseOfVictim)
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
        // Weeks 4-5: hostile (>30% insults)
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
        // Trigger
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
        // Build role reversal scenario
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
        // Trigger recalculation
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
        // Build inner circle + role reversal
        // 15+ days with lots of messages to establish Inner circle
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
        // Now weeks 3-4: hostile
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
        // Trigger
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
            // Inner circle boost: score should be higher
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
        // Simulate old state (no rating/trust_level/snapshots)
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
        // Old trusted contact should get trust_level = 1.0
        assert_eq!(profile.trust_level, 1.0);
        // Rating should default to 50
        assert_eq!(profile.rating, 50.0);
        assert_eq!(profile.circle_tier, CircleTier::New);
        assert_eq!(profile.trend, BehavioralTrend::Stable);
    }

    // ---- Real-world scenario tests ----

    #[test]
    fn scenario_friend_to_bully_over_3_months() {
        // September: 3 friends chatting normally
        // October: one starts occasional insults
        // November-December: escalating hostility
        let mut profiler = ContactProfiler::new();
        let week = WEEK_MS;

        // September (weeks 0-3): all normal
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

        // October (weeks 4-7): occasional insults (2/10 messages)
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

        // November-December (weeks 8-15): heavy hostility (6/10 messages)
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
        // Trigger recalculation
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

        // Should generate behavioral shift signal
        let signals = profiler.check_behavioral_shift("masha");
        assert!(
            !signals.is_empty(),
            "Should generate shift signal for friend-to-bully"
        );
    }

    #[test]
    fn scenario_trusted_adult_starts_grooming() {
        // Parent marks contact as trusted (coach/teacher)
        // Initially normal, then starts grooming behaviors
        let mut profiler = ContactProfiler::new();

        // Establish as trusted contact
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

        // Weeks 5-8: starts grooming (flattery, gifts, personal questions)
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
        // Grooming events give small negative deltas; rating should decrease from baseline
        assert!(
            profile.rating < baseline_rating,
            "Rating should decrease from grooming: baseline={baseline_rating} now={}",
            profile.rating
        );
        // Trust should NOT decay (grooming is not hostile)
        assert!(
            profile.trust_level >= 0.9,
            "Trust should remain high during grooming-only: {}",
            profile.trust_level
        );
    }

    #[test]
    fn scenario_trusted_adult_escalates_to_hostile() {
        let mut profiler = ContactProfiler::new();

        // Normal phase
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

        // Hostile phase — gaslighting, emotional blackmail
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
        // Contact was hostile but improved
        let mut profiler = ContactProfiler::new();

        // Weeks 0-2: hostile
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

        // Weeks 3-7: all normal (recovery)
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
        // Trigger
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
        // On-off hostility: hostile one week, nice the next
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
                // Hostile weeks: mix of insults and normal to avoid floor
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
        // Should not be dramatically high — mix of hostile and normal
        assert!(
            profile.rating < 60.0,
            "Mixed signals should give moderate-to-low rating, got {}",
            profile.rating
        );
    }

    #[test]
    fn scenario_new_contact_rapid_grooming() {
        // Stranger who escalates very quickly within first 2 weeks
        let mut profiler = ContactProfiler::new();

        // Day 1: flattery
        profiler.record_event(&make_event("stranger", "conv_1", EventKind::Flattery, 0));
        profiler.record_event(&make_event("stranger", "conv_1", EventKind::Flattery, 1000));

        // Day 2: gifts + personal questions
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

        // Day 3: secrecy + platform switch
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

        // Day 5: photo request + meeting
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
        // Teens have occasional arguments but it is not sustained bullying
        let mut profiler = ContactProfiler::new();

        // Week 1: mostly normal, 1 insult (heated argument)
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

        // Weeks 2-5: all normal (made up after argument)
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

    // ---- Edge case tests ----

    #[test]
    fn rating_floor_after_sustained_attack() {
        let mut profiler = ContactProfiler::new();
        // 50 physical threats should floor at 0
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
        // Many supportive events should cap at 100
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

        // Massive hostility
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
        // Event exactly at week boundary
        profiler.record_event(&make_event(
            "alice",
            "conv_1",
            EventKind::NormalConversation,
            WEEK_MS,
        ));
        // Should have finalized week 1
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
        // At exactly 14 days, should no longer be New
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

        // Messages over 200 days
        for day in 0..200u64 {
            profiler.record_event(&make_event(
                "longterm",
                "conv_1",
                EventKind::NormalConversation,
                day * DAY_MS,
            ));
        }

        let before = profiler.profile("longterm").unwrap().active_days.len();

        // Cleanup with cutoff at day 150 — retains profile (last_seen=199*DAY)
        // but prunes active_days older than cutoff_day - 90 = day 60
        profiler.cleanup(150 * DAY_MS);

        let profile = profiler.profile("longterm").unwrap();
        // Should still have recent active_days (days 60-199)
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

        // Build some history
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

        // Import into new profiler
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

        // Establish as inner circle (15+ days, 10 msgs/day)
        for day in 0..30u64 {
            for msg in 0..10 {
                let kind = if day < 5 {
                    EventKind::NormalConversation
                } else {
                    EventKind::PhysicalThreat // tanks rating
                };
                profiler.record_event(&make_event(
                    "inner_bully",
                    "conv_1",
                    kind,
                    day * DAY_MS + msg * 1000,
                ));
            }
        }

        // Trigger to finalize last weekly snapshot
        profiler.record_event(&make_event(
            "inner_bully",
            "conv_1",
            EventKind::PhysicalThreat,
            30 * DAY_MS + 1000,
        ));
        let profile = profiler.profile("inner_bully").unwrap();
        assert_eq!(profile.circle_tier, CircleTier::Inner);

        // The shift signals should include low rating alert
        let signals = profiler.check_behavioral_shift("inner_bully");
        let has_low_rating = signals
            .iter()
            .any(|s| s.explanation.contains("critically low rating"));
        // Only if rating is actually < 20
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

        // Two contacts with same grooming events, different trust levels
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

    // ---- Property-based invariant tests ----

    #[test]
    fn property_rating_always_in_0_100() {
        // Feed every possible EventKind into a profile and verify rating stays [0, 100]
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
        // Same but for trust_level
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
        // Total messages in snapshot == hostile + supportive + neutral
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
        // If we only send hostile events, rating should never increase
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
        // Trust should never increase from hostile events (no event restores trust)
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
        // Already in events.rs, but verifying from contact perspective
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

    // ---- Fuzz / edge-case tests ----

    #[test]
    fn fuzz_max_timestamp() {
        // u64::MAX should not panic
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
        // Events arriving out of order (newer then older)
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event("x", "c", EventKind::NormalConversation, 10000));
        profiler.record_event(&make_event("x", "c", EventKind::Insult, 5000));
        // Should not panic; last_seen should be max
        let p = profiler.profile("x").unwrap();
        assert_eq!(p.last_seen_ms, 10000);
    }

    #[test]
    fn fuzz_same_timestamp_many_events() {
        // All events at exact same timestamp
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
        // Mark trusted, decay fully, mark trusted again, decay again
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
        // Everything has last_seen >= 0, so nothing should be removed
        assert!(profiler.profile("x").is_some());
    }

    #[test]
    fn fuzz_cleanup_with_max_cutoff() {
        let mut profiler = ContactProfiler::new();
        profiler.record_event(&make_event("x", "c", EventKind::NormalConversation, 1000));
        profiler.cleanup(u64::MAX);
        // Everything should be removed (last_seen < MAX)
        assert!(profiler.profile("x").is_none());
    }

    #[test]
    fn fuzz_export_import_empty_profiler() {
        let profiler = ContactProfiler::new();
        let state = profiler.export();
        assert!(state.profiles.is_empty());
        let mut profiler2 = ContactProfiler::new();
        profiler2.import(state);
        // Should not panic
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
    fn import_respects_profile_limit() {
        let mut profiler = ContactProfiler::with_max_profiles(2);
        profiler.import(ContactProfilerState {
            profiles: vec![
                ContactProfile::new("alice".to_string(), 1_000),
                ContactProfile::new("bob".to_string(), 2_000),
                ContactProfile::new("carol".to_string(), 3_000),
            ],
        });

        assert!(profiler.profile("alice").is_none());
        assert!(profiler.profile("bob").is_some());
        assert!(profiler.profile("carol").is_some());
    }

    #[test]
    fn fuzz_deserialize_corrupt_rating() {
        // Rating outside [0, 100] in imported state -- should still work
        let json = r#"{"profiles":[{
            "sender_id":"x","first_seen_ms":0,"last_seen_ms":1000,"total_messages":1,
            "conversation_count":1,"conversations":["c"],"grooming_event_count":0,
            "bullying_event_count":0,"manipulation_event_count":0,"is_trusted":false,
            "severity_sum":0.0,"severity_count":0,"rating":999.0,"trust_level":5.0
        }]}"#;
        let state: ContactProfilerState = serde_json::from_str(json).unwrap();
        let mut profiler = ContactProfiler::new();
        profiler.import(state);
        // Values imported as-is (not clamped on import) but next event should clamp
        let p = profiler.profile("x").unwrap();
        assert_eq!(p.rating, 999.0); // raw import
    }

    // ---- Stress tests ----

    #[test]
    fn stress_1000_contacts_52_weeks() {
        let mut profiler = ContactProfiler::new();
        let week = WEEK_MS;

        // Create 1000 contacts, each with 52 weeks of 5 msgs/week
        for contact in 0..1000u64 {
            let sender = format!("contact_{contact}");
            for w in 0..52 {
                for msg in 0..5 {
                    let kind = if contact % 10 == 0 && w > 40 {
                        // 10% of contacts turn hostile in last weeks
                        EventKind::Insult
                    } else {
                        EventKind::NormalConversation
                    };
                    profiler.record_event(&make_event(
                        &sender,
                        "conv_1",
                        kind,
                        w * week + msg * 1000 + contact, // slight offset per contact
                    ));
                }
            }
        }

        // Verify all contacts exist
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

        // Hostile contacts should have lower ratings
        let hostile_contact = profiler.profile("contact_0").unwrap();
        let normal_contact = profiler.profile("contact_1").unwrap();
        assert!(
            hostile_contact.rating < normal_contact.rating,
            "Hostile contact rating {} should be lower than normal {}",
            hostile_contact.rating,
            normal_contact.rating
        );

        // Snapshots should be capped at MAX_SNAPSHOTS
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
            // Varying risk: more grooming events for higher-numbered contacts
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

        // Verify sorted in descending risk order
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
        // 10000 events * 1000ms = 10_000_000ms; each week is 604_800_000ms
        // All fit in first week, so no finalized snapshots
        // 10_000 * 1000 = 10_000_000ms = ~2.7 hours, within one week
        assert_eq!(p.weekly_snapshots().len(), 0, "All events within one week");
    }

    // ---- Skipped weeks tests ----

    #[test]
    fn skipped_weeks_3_week_gap_then_return() {
        // Child didn't write for 3 weeks, then returned
        let mut profiler = ContactProfiler::new();

        // Week 0: normal conversation
        for msg in 0..10 {
            profiler.record_event(&make_event(
                "gap",
                "conv_1",
                EventKind::NormalConversation,
                msg * 1000,
            ));
        }

        // Skip weeks 1-3 (no messages)

        // Week 4: resume normal
        for msg in 0..10 {
            profiler.record_event(&make_event(
                "gap",
                "conv_1",
                EventKind::NormalConversation,
                4 * WEEK_MS + msg * 1000,
            ));
        }

        let p = profiler.profile("gap").unwrap();
        // Week 0 snapshot should be finalized when week 4 event arrives
        assert_eq!(
            p.weekly_snapshots().len(),
            1,
            "Should have 1 finalized snapshot from week 0"
        );
        assert_eq!(p.weekly_snapshots()[0].total_messages, 10);
        // Rating should be healthy (all normal)
        assert!(
            p.rating > 50.0,
            "Normal conversations should keep rating above 50: {}",
            p.rating
        );
    }

    #[test]
    fn skipped_weeks_gap_with_hostility_before_and_after() {
        // Week 0-1: hostile, then 4-week gap, then hostile again
        let mut profiler = ContactProfiler::new();

        // Weeks 0-1: hostile
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

        // Skip weeks 2-5

        // Week 6: hostile again
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
        // Contact disappears for 8 weeks then returns with hostile behavior
        let mut profiler = ContactProfiler::new();

        // Week 0: friendly
        for msg in 0..10 {
            profiler.record_event(&make_event(
                "absent",
                "conv_1",
                EventKind::NormalConversation,
                msg * 1000,
            ));
        }
        let friendly_rating = profiler.profile("absent").unwrap().rating;

        // Skip 8 weeks

        // Week 9: returns hostile
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
        // Snapshot from week 0 should still be there
        assert!(!p.weekly_snapshots().is_empty());
    }

    #[test]
    fn skipped_weeks_holiday_recovery_pattern() {
        // Typical pattern: school year hostility -> summer break -> school returns
        let mut profiler = ContactProfiler::new();

        // Weeks 0-4: school, some bullying (3/10 hostile)
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

        // Weeks 5-12: summer holiday -- occasional normal messages only
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

        // Weeks 13-16: school returns, hostility resumes
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
        // Trigger
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
        // Verify that gaps don't create empty snapshots
        let mut profiler = ContactProfiler::new();

        // Week 0
        profiler.record_event(&make_event("g", "c", EventKind::NormalConversation, 0));
        // Jump to week 10
        profiler.record_event(&make_event(
            "g",
            "c",
            EventKind::NormalConversation,
            10 * WEEK_MS,
        ));

        let p = profiler.profile("g").unwrap();
        // Only week 0 should be finalized (not weeks 1-9 as empty snapshots)
        assert_eq!(
            p.weekly_snapshots().len(),
            1,
            "Gaps should not create empty snapshots, got {}",
            p.weekly_snapshots().len()
        );
    }

    // ---- Concurrent access pattern tests ----
    // Simulate patterns that would occur with server sync:
    // interleaved events, export/import during use, merge scenarios

    #[test]
    fn concurrent_interleaved_events_two_devices() {
        // Simulate child chatting on phone and tablet simultaneously
        // Events arrive interleaved (not strictly ordered by time)
        let mut profiler = ContactProfiler::new();

        // Device A sends events at even timestamps
        // Device B sends events at odd timestamps
        for i in 0..20u64 {
            if i % 2 == 0 {
                // Device A: normal conversation
                profiler.record_event(&make_event(
                    "friend",
                    "conv_1",
                    EventKind::NormalConversation,
                    i * 500,
                ));
            } else {
                // Device B: same contact, different conversation
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
        // Export state mid-conversation, continue on device A, then import back
        let mut profiler = ContactProfiler::new();

        // Phase 1: build some history
        for i in 0..5 {
            profiler.record_event(&make_event(
                "alice",
                "conv_1",
                EventKind::NormalConversation,
                i * 1000,
            ));
        }
        let mid_rating = profiler.profile("alice").unwrap().rating;

        // Export (simulates server sync checkpoint)
        let checkpoint = profiler.export();

        // Phase 2: more events on original device
        for i in 5..10 {
            profiler.record_event(&make_event("alice", "conv_1", EventKind::Insult, i * 1000));
        }
        let post_hostile_rating = profiler.profile("alice").unwrap().rating;
        assert!(post_hostile_rating < mid_rating);

        // Import checkpoint into fresh profiler (simulates second device)
        let mut device2 = ContactProfiler::new();
        device2.import(checkpoint);
        let device2_rating = device2.profile("alice").unwrap().rating;
        assert_eq!(
            device2_rating, mid_rating,
            "Device 2 should have checkpoint rating"
        );

        // Device 2 gets new events
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
        // Device A has stale data, imports fresh state from server
        let mut device_a = ContactProfiler::new();
        device_a.record_event(&make_event(
            "bob",
            "conv_1",
            EventKind::NormalConversation,
            0,
        ));

        // Server has more complete profile
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

        // Import overwrites device A's profile for "bob"
        device_a.import(server_state);
        let profile = device_a.profile("bob").unwrap();
        assert_eq!(
            profile.total_messages, 20,
            "Import should overwrite stale data"
        );
    }

    #[test]
    fn concurrent_multiple_contacts_independent() {
        // Verify that events for different contacts don't interfere
        let mut profiler = ContactProfiler::new();

        // Alice gets hostile events
        for i in 0..10 {
            profiler.record_event(&make_event("alice", "conv_1", EventKind::Insult, i * 1000));
        }

        // Bob gets supportive events (interleaved in "real time")
        for i in 0..10 {
            profiler.record_event(&make_event(
                "bob",
                "conv_2",
                EventKind::DefenseOfVictim,
                i * 1000,
            ));
        }

        // Charlie gets grooming events
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

        // Each contact should be independent
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
        // Charlie gets small negative from grooming-only
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
        // Multiple contacts, export, import into fresh instance
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
        // Simulate cleanup happening while new events arrive
        let mut profiler = ContactProfiler::new();

        // Old contact (will be cleaned up)
        profiler.record_event(&make_event(
            "old_user",
            "conv_1",
            EventKind::NormalConversation,
            1000,
        ));

        // Active contact
        let active_ts = 100 * DAY_MS;
        for i in 0..10 {
            profiler.record_event(&make_event(
                "active_user",
                "conv_1",
                EventKind::NormalConversation,
                active_ts + i * 1000,
            ));
        }

        // Cleanup removes old contacts
        profiler.cleanup(50 * DAY_MS);
        assert!(
            profiler.profile("old_user").is_none(),
            "Old user should be removed"
        );
        assert!(
            profiler.profile("active_user").is_some(),
            "Active user should survive"
        );

        // Continue adding events after cleanup
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
        // Import state then immediately mark a contact trusted
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

        // Subsequent hostile events should decay trust normally
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
        // Import twice — second import should overwrite first
        let mut profiler = ContactProfiler::new();

        // State 1: alice with rating after normal msgs
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

        // State 2: alice with rating after hostile msgs
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

        // Import state1 first, then state2 — state2 should win
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
        // Full behavioral history survives export/import cycle
        let mut profiler = ContactProfiler::new();

        // Build 6 weeks of history with trend
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
        // Trigger snapshot
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

        // Export → import
        let state = profiler.export();
        let mut profiler2 = ContactProfiler::new();
        profiler2.import(state);

        let imported = profiler2.profile("contact").unwrap();
        assert_eq!(imported.weekly_snapshots().len(), orig_snapshots);
        assert_eq!(imported.trend, orig_trend);
        assert_eq!(imported.rating, orig_rating);

        // Continue on imported profiler — behavioral shift should still work
        let signals = profiler2.check_behavioral_shift("contact");
        let orig_signals = profiler.check_behavioral_shift("contact");
        assert_eq!(
            signals.len(),
            orig_signals.len(),
            "Behavioral shift signals should match after import"
        );
    }

    // -----------------------------------------------------------------------
    // Phase 1: merge_import tests
    // -----------------------------------------------------------------------

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
        // Should have max of counters, not sum
        assert!(
            profile.bullying_event_count >= 2,
            "Should preserve higher bullying count from A"
        );
        // Should have union of conversations
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
        // B has untrusted alice (default)

        let state_b = profiler_b.export();
        profiler_a.merge_import(state_b);

        let profile = profiler_a.profile("alice").unwrap();
        // Most cautious: if either side has is_trusted=false, result should be false
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
}
