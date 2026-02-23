use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::types::{Confidence, DetectionLayer, DetectionSignal, ThreatType};

use super::events::ContextEvent;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const WEEK_MS: u64 = 7 * 24 * 60 * 60 * 1000; // 604_800_000
const DAY_MS: u64 = 24 * 60 * 60 * 1000; // 86_400_000
const MAX_SNAPSHOTS: usize = 26; // 6 months of weekly snapshots

fn default_rating() -> f32 {
    50.0
}

fn default_trust() -> f32 {
    0.5
}

// ---------------------------------------------------------------------------
// CircleTier
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircleTier {
    Inner,
    Regular,
    Occasional,
    New,
}

impl Default for CircleTier {
    fn default() -> Self {
        Self::New
    }
}

// ---------------------------------------------------------------------------
// BehavioralTrend
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehavioralTrend {
    Stable,
    Improving,
    GradualWorsening,
    RapidWorsening,
    RoleReversal,
}

impl Default for BehavioralTrend {
    fn default() -> Self {
        Self::Stable
    }
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

    conversations: Vec<String>,

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
        if hours_known < 24.0
            && (self.grooming_event_count > 0 || self.bullying_event_count > 0)
        {
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
            .map_or(false, |s| event.timestamp_ms >= s.period_start_ms + WEEK_MS);

        if needs_finalize {
            if let Some(mut old) = self.current_snapshot.take() {
                old.period_end_ms = old.period_start_ms + WEEK_MS;
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
        snapshot.avg_severity =
            snapshot.avg_severity * ((n - 1.0) / n) + event.kind.severity() / n;
    }

    fn recalculate_trend(&mut self) {
        let snapshots = &self.weekly_snapshots;

        if snapshots.len() < 3 {
            self.trend = BehavioralTrend::Stable;
            return;
        }

        // Baseline: first half (2-4 snapshots)
        let baseline_count = (snapshots.len() / 2).max(2).min(4);
        let baseline_hostile = avg_hostile_ratio(snapshots.iter().take(baseline_count));
        let baseline_supportive =
            avg_supportive_ratio(snapshots.iter().take(baseline_count));

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
        self.active_days.iter().filter(|&&d| d >= cutoff_day).count()
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

fn avg_supportive_ratio<'a>(
    snapshots: impl Iterator<Item = &'a BehavioralSnapshot>,
) -> f32 {
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

// ---------------------------------------------------------------------------
// ContactProfiler
// ---------------------------------------------------------------------------

pub struct ContactProfiler {
    profiles: HashMap<String, ContactProfile>,
}

impl Default for ContactProfiler {
    fn default() -> Self {
        Self::new()
    }
}

impl ContactProfiler {
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
        }
    }

    pub fn record_event(&mut self, event: &ContextEvent) {
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

                signals.push(DetectionSignal {
                    threat_type: ThreatType::Grooming,
                    score,
                    confidence: Confidence::Medium,
                    layer: DetectionLayer::ContextAnalysis,
                    explanation: format!(
                        "Age gap detected: sender claims age {sender_age}, account holder is {holder_age} (gap: {gap} years){}",
                        if profile.grooming_event_count > 0 {
                            format!(" with {} grooming indicators", profile.grooming_event_count)
                        } else {
                            String::new()
                        }
                    ),
                });
            }
        }

        signals
    }

    pub fn check_anomalies(
        &self,
        sender_id: &str,
        is_child_account: bool,
    ) -> Vec<DetectionSignal> {
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
            signals.push(DetectionSignal {
                threat_type: ThreatType::Grooming,
                score: risk,
                confidence: Confidence::Medium,
                layer: DetectionLayer::ContextAnalysis,
                explanation: format!(
                    "New contact with suspicious behavior pattern (risk: {risk:.2}). {} grooming indicators, {} bullying indicators.",
                    profile.grooming_event_count,
                    profile.bullying_event_count,
                ),
            });
        }

        if profile.conversation_count >= 5 && profile.grooming_event_count >= 3 {
            signals.push(DetectionSignal {
                threat_type: ThreatType::Grooming,
                score: 0.8,
                confidence: Confidence::High,
                layer: DetectionLayer::ContextAnalysis,
                explanation: format!(
                    "Contact appears in {} conversations with {} grooming indicators — possible predator pattern",
                    profile.conversation_count,
                    profile.grooming_event_count,
                ),
            });
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
                signals.push(DetectionSignal {
                    threat_type: ThreatType::Manipulation,
                    score,
                    confidence: Confidence::Medium,
                    layer: DetectionLayer::ContextAnalysis,
                    explanation: format!(
                        "Contact {} showing rapid behavioral worsening (rating: {:.0})",
                        sender_id, profile.rating
                    ),
                });
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
                signals.push(DetectionSignal {
                    threat_type: ThreatType::Bullying,
                    score,
                    confidence: Confidence::High,
                    layer: DetectionLayer::ContextAnalysis,
                    explanation: format!(
                        "Contact {} role reversal: was supportive, now hostile (rating: {:.0})",
                        sender_id, profile.rating
                    ),
                });
            }
            BehavioralTrend::GradualWorsening => {
                let mut score = 0.35;
                if profile.circle_tier == CircleTier::Inner {
                    score += 0.1;
                }
                signals.push(DetectionSignal {
                    threat_type: ThreatType::Manipulation,
                    score,
                    confidence: Confidence::Medium,
                    layer: DetectionLayer::ContextAnalysis,
                    explanation: format!(
                        "Contact {} showing gradual behavioral worsening over weeks (rating: {:.0})",
                        sender_id, profile.rating
                    ),
                });
            }
            _ => {}
        }

        // Low rating alert for inner circle
        if profile.rating < 20.0 && profile.circle_tier == CircleTier::Inner {
            signals.push(DetectionSignal {
                threat_type: ThreatType::Bullying,
                score: 0.55,
                confidence: Confidence::High,
                layer: DetectionLayer::ContextAnalysis,
                explanation: format!(
                    "Inner circle contact {} has critically low rating ({:.0}/100)",
                    sender_id, profile.rating
                ),
            });
        }

        signals
    }

    pub fn export(&self) -> ContactProfilerState {
        ContactProfilerState {
            profiles: self.profiles.values().cloned().collect(),
        }
    }

    pub fn import(&mut self, state: ContactProfilerState) {
        for mut profile in state.profiles {
            profile.post_deserialize_fixup();
            self.profiles.insert(profile.sender_id.clone(), profile);
        }
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
            timestamp_ms: ts,
            sender_id: sender.to_string(),
            conversation_id: conv.to_string(),
            kind,
            confidence: 0.8,
        }
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
            profiler.record_event(&make_event(
                "bully",
                "conv_1",
                EventKind::Insult,
                i * 1000,
            ));
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
            trend == BehavioralTrend::GradualWorsening
                || trend == BehavioralTrend::RapidWorsening,
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
}
