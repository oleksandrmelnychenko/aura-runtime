use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::types::{Confidence, DetectionLayer, DetectionSignal, ThreatType};

use super::events::ContextEvent;

pub struct ContactProfiler {
    profiles: HashMap<String, ContactProfile>,
}

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
        if hours_known < 24.0 && (self.grooming_event_count > 0 || self.bullying_event_count > 0) {
            score += 0.1;
        }

        if self.is_trusted {
            score *= 0.5;
        }

        score.min(1.0)
    }
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

    pub fn export(&self) -> ContactProfilerState {
        ContactProfilerState {
            profiles: self.profiles.values().cloned().collect(),
        }
    }

    pub fn import(&mut self, state: ContactProfilerState) {
        for profile in state.profiles {
            self.profiles.insert(profile.sender_id.clone(), profile);
        }
    }

    pub fn cleanup(&mut self, cutoff_ms: u64) {
        self.profiles.retain(|_, p| p.last_seen_ms >= cutoff_ms);
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
}
