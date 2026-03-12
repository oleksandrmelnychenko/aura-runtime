use std::collections::HashSet;

use crate::types::{Confidence, ConversationType, DetectionSignal, SignalFamily, ThreatType};

use super::contact::ContactProfiler;
use super::events::EventKind;
use super::tracker::ConversationTimeline;

pub struct GroomingDetector {
    strict_mode: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum GroomingStage {
    TrustBuilding = 1,

    FinancialDependency = 2,

    Isolation = 3,

    BoundaryCrossing = 4,

    Sexualization = 5,

    Control = 6,
}

impl GroomingDetector {
    pub fn new(strict_mode: bool) -> Self {
        Self { strict_mode }
    }

    pub fn analyze(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        window_start: u64,
        contact_profiler: &ContactProfiler,
    ) -> Vec<DetectionSignal> {
        let events = timeline.events_from_sender(sender_id, window_start);
        if events.is_empty() {
            return Vec::new();
        }

        let mut signals = Vec::new();

        let mut stage_counts: [usize; 6] = [0; 6];
        let mut stage_timestamps: [Option<u64>; 6] = [None; 6];

        for event in &events {
            if let Some(stage) = self.classify_stage(&event.kind) {
                let idx = stage as usize - 1;
                stage_counts[idx] += 1;

                if stage_timestamps[idx].is_none() {
                    stage_timestamps[idx] = Some(event.timestamp_ms);
                }
            }
        }

        let stages_present: usize = stage_counts.iter().filter(|&&c| c > 0).count();

        if stages_present == 0 {
            return signals;
        }

        let mut score: f32 = 0.0;

        score += match stages_present {
            1 => 0.15,
            2 => 0.35,
            3 => 0.55,
            4 => 0.75,
            5 => 0.90,
            6 => 0.95,
            _ => 0.0,
        };

        if self.stages_escalate(&stage_timestamps) {
            score += 0.1;
        }

        if let Some(speed_bonus) = self.escalation_speed_bonus(&stage_timestamps) {
            score += speed_bonus;
        }

        if contact_profiler.is_new_contact(sender_id) {
            score += 0.05;
        }

        if contact_profiler.contacts_many_minors(sender_id) {
            score += 0.1;
        }

        if let Some(profile) = contact_profiler.profile(sender_id) {
            if let Some(age) = profile.inferred_age {
                if age >= 18 {
                    score += 0.1;
                }
            }
        }

        if self.strict_mode {
            score += 0.05;
        }

        let peer_courtship_dampening = self.peer_courtship_dampening(
            timeline,
            sender_id,
            window_start,
            &stage_counts,
            contact_profiler,
        );
        if peer_courtship_dampening > 0.0 {
            score = (score - peer_courtship_dampening).max(0.0);
        }

        score = score.min(1.0);

        let threshold = if self.strict_mode { 0.25 } else { 0.35 };

        if score >= threshold {
            let explanation = self.build_explanation(
                stages_present,
                &stage_counts,
                score,
                peer_courtship_dampening > 0.0,
            );
            signals.push(DetectionSignal::context(
                ThreatType::Grooming,
                score,
                self.score_to_confidence(score),
                SignalFamily::Conversation,
                "conversation.grooming.stage_sequence",
                explanation,
            ));
        }

        if stages_present == 1
            && stage_counts[0] >= 3
            && self.strict_mode
            && contact_profiler.is_new_contact(sender_id)
        {
            signals.push(DetectionSignal::context(
                ThreatType::Grooming,
                0.3,
                Confidence::Low,
                SignalFamily::Conversation,
                "conversation.grooming.new_contact_flattery",
                "New contact showing excessive flattery toward a minor — monitoring closely",
            ));
        }

        // Secret Keeping Escalation: repeated secrecy requests from same sender
        let secrecy_count = events
            .iter()
            .filter(|e| e.kind == EventKind::SecrecyRequest)
            .count();
        if secrecy_count >= 3 {
            let secrecy_score = (0.6 + (secrecy_count as f32 - 3.0) * 0.1).min(0.9);
            let already_has_higher = signals.iter().any(|s| s.score >= secrecy_score);
            if !already_has_higher {
                signals.push(DetectionSignal::context(
                    ThreatType::Grooming,
                    secrecy_score,
                    if secrecy_count >= 5 {
                        Confidence::High
                    } else {
                        Confidence::Medium
                    },
                    SignalFamily::Conversation,
                    "conversation.grooming.repeated_secrecy",
                    format!(
                        "Repeated secrecy requests detected: {} instances of 'keep this secret' from the same sender",
                        secrecy_count
                    ),
                ));
            }
        }

        signals
    }

    fn peer_courtship_dampening(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        window_start: u64,
        stage_counts: &[usize; 6],
        contact_profiler: &ContactProfiler,
    ) -> f32 {
        if timeline.conversation_type != ConversationType::Direct {
            return 0.0;
        }

        let has_trust_building = stage_counts[0] > 0;
        let has_boundary_crossing = stage_counts[3] > 0;
        let has_higher_risk_stage = stage_counts[1] > 0
            || stage_counts[2] > 0
            || stage_counts[4] > 0
            || stage_counts[5] > 0;
        if !has_trust_building || !has_boundary_crossing || has_higher_risk_stage {
            return 0.0;
        }

        if contact_profiler.contacts_many_minors(sender_id) {
            return 0.0;
        }

        if contact_profiler
            .profile(sender_id)
            .and_then(|profile| profile.inferred_age)
            .is_some_and(|age| age >= 18)
        {
            return 0.0;
        }

        let sender_events = timeline.events_from_sender(sender_id, window_start);
        if sender_events.len() < 2 || sender_events.len() > 3 {
            return 0.0;
        }

        if sender_events.iter().any(|event| {
            !matches!(
                event.kind,
                EventKind::Flattery
                    | EventKind::LoveBombing
                    | EventKind::CasualMeetingRequest
                    | EventKind::MeetingRequest
            )
        }) {
            return 0.0;
        }

        let all_events = timeline.events_since(window_start);
        let mut other_senders: HashSet<&str> = HashSet::new();
        let mut other_events = Vec::new();
        for event in all_events {
            if event.sender_id != sender_id {
                other_senders.insert(event.sender_id.as_str());
                other_events.push(event);
            }
        }

        if other_senders.len() != 1 || other_events.is_empty() {
            return 0.0;
        }

        let first_sender_ts = sender_events.iter().map(|event| event.timestamp_ms).min();
        let last_sender_ts = sender_events.iter().map(|event| event.timestamp_ms).max();
        let has_interleaved_reply = match (first_sender_ts, last_sender_ts) {
            (Some(first_ts), Some(last_ts)) => other_events
                .iter()
                .any(|event| event.timestamp_ms > first_ts && event.timestamp_ms < last_ts),
            _ => false,
        };
        if !has_interleaved_reply {
            return 0.0;
        }

        let reciprocal_meeting = other_events.iter().any(|event| {
            matches!(
                event.kind,
                EventKind::CasualMeetingRequest | EventKind::MeetingRequest
            )
        });
        let reciprocal_social_reply = other_events.iter().any(|event| {
            matches!(
                event.kind,
                EventKind::NormalConversation | EventKind::Flattery | EventKind::LoveBombing
            )
        });
        if !reciprocal_meeting && !reciprocal_social_reply {
            return 0.0;
        }

        if reciprocal_meeting {
            0.20
        } else {
            0.15
        }
    }

    fn classify_stage(&self, kind: &EventKind) -> Option<GroomingStage> {
        match kind {
            EventKind::Flattery
            | EventKind::LoveBombing
            | EventKind::IdentityErosion
            | EventKind::FakeVulnerability => Some(GroomingStage::TrustBuilding),
            EventKind::GiftOffer | EventKind::MoneyOffer | EventKind::FinancialGrooming => {
                Some(GroomingStage::FinancialDependency)
            }
            EventKind::SecrecyRequest | EventKind::PlatformSwitch | EventKind::NetworkPoisoning => {
                Some(GroomingStage::Isolation)
            }
            EventKind::PersonalInfoRequest
            | EventKind::PhotoRequest
            | EventKind::VideoCallRequest
            | EventKind::CasualMeetingRequest => Some(GroomingStage::BoundaryCrossing),
            EventKind::PiiSelfDisclosure => Some(GroomingStage::BoundaryCrossing),
            EventKind::SexualContent | EventKind::AgeInappropriate | EventKind::FalseConsensus => {
                Some(GroomingStage::Sexualization)
            }
            EventKind::EmotionalBlackmail | EventKind::GuiltTripping | EventKind::DebtCreation => {
                Some(GroomingStage::Control)
            }
            _ => None,
        }
    }

    fn stages_escalate(&self, timestamps: &[Option<u64>; 6]) -> bool {
        let mut last_ts = 0u64;
        let mut ordered = true;
        for ts in timestamps.iter().flatten() {
            if *ts < last_ts {
                ordered = false;
                break;
            }
            last_ts = *ts;
        }
        ordered && timestamps.iter().filter(|t| t.is_some()).count() >= 2
    }

    fn escalation_speed_bonus(&self, timestamps: &[Option<u64>; 6]) -> Option<f32> {
        let mut present: Vec<u64> = timestamps.iter().filter_map(|t| *t).collect();
        if present.len() < 2 {
            return None;
        }

        // Stage slots are semantic order, not chronological order. Sort before measuring span.
        present.sort_unstable();
        let first = present[0];
        let last = present[present.len() - 1];
        let span_hours = (last - first) as f32 / (1000.0 * 60.0 * 60.0);

        if span_hours < 2.0 && present.len() >= 3 {
            Some(0.15)
        } else if span_hours < 24.0 && present.len() >= 3 {
            Some(0.1)
        } else if span_hours < 72.0 && present.len() >= 4 {
            Some(0.05)
        } else {
            None
        }
    }

    fn score_to_confidence(&self, score: f32) -> Confidence {
        if score >= 0.7 {
            Confidence::High
        } else if score >= 0.4 {
            Confidence::Medium
        } else {
            Confidence::Low
        }
    }

    fn build_explanation(
        &self,
        stages: usize,
        counts: &[usize; 6],
        score: f32,
        peer_courtship_dampened: bool,
    ) -> String {
        let stage_names = [
            "trust building",
            "financial dependency",
            "isolation",
            "boundary crossing",
            "sexualization",
            "control",
        ];
        let active: Vec<&str> = counts
            .iter()
            .enumerate()
            .filter(|(_, &c)| c > 0)
            .map(|(i, _)| stage_names[i])
            .collect();

        let mut explanation = format!(
            "Grooming pattern detected: {stages} of 6 stages present ({active}). Risk score: {score:.2}.",
            active = active.join(", ")
        );
        if peer_courtship_dampened {
            explanation.push_str(
                " Mutual peer-style reciprocity and public-meeting context reduced this early-stage score.",
            );
        }
        explanation
    }
}

#[cfg(test)]
mod tests {
    use super::super::contact::ContactProfiler;
    use super::super::events::{ContextEvent, EventKind};
    use super::super::tracker::ConversationTimeline;
    use super::*;

    fn make_timeline(events: Vec<(EventKind, u64)>) -> ConversationTimeline {
        let mut timeline = ConversationTimeline::new("conv_1".to_string(), 500);
        for (kind, ts) in events {
            timeline.push(ContextEvent {
                event_id: 0,
                timestamp_ms: ts,
                sender_id: "predator".to_string(),
                conversation_id: "conv_1".to_string(),
                kind,
                confidence: 0.8,
            });
        }
        timeline
    }

    fn make_multi_sender_timeline(events: Vec<(&str, EventKind, u64)>) -> ConversationTimeline {
        let mut timeline = ConversationTimeline::new("conv_1".to_string(), 500);
        for (sender, kind, ts) in events {
            timeline.push(ContextEvent {
                event_id: 0,
                timestamp_ms: ts,
                sender_id: sender.to_string(),
                conversation_id: "conv_1".to_string(),
                kind,
                confidence: 0.8,
            });
        }
        timeline
    }

    #[test]
    fn no_grooming_in_normal_conversation() {
        let detector = GroomingDetector::new(true);
        let timeline = make_timeline(vec![
            (EventKind::NormalConversation, 1000),
            (EventKind::NormalConversation, 2000),
            (EventKind::NormalConversation, 3000),
        ]);
        let profiler = ContactProfiler::new();

        let signals = detector.analyze(&timeline, "predator", 0, &profiler);
        assert!(signals.is_empty());
    }

    #[test]
    fn single_stage_low_concern() {
        let detector = GroomingDetector::new(true);
        let timeline = make_timeline(vec![(EventKind::Flattery, 1000)]);
        let profiler = ContactProfiler::new();

        let signals = detector.analyze(&timeline, "predator", 0, &profiler);

        assert!(signals.is_empty() || signals[0].score < 0.3);
    }

    #[test]
    fn two_stages_moderate_concern() {
        let detector = GroomingDetector::new(true);
        let timeline = make_timeline(vec![
            (EventKind::Flattery, 1000),
            (EventKind::GiftOffer, 2000),
            (EventKind::SecrecyRequest, 3000),
        ]);
        let profiler = ContactProfiler::new();

        let signals = detector.analyze(&timeline, "predator", 0, &profiler);
        assert!(!signals.is_empty());

        assert!(signals[0].score >= 0.35);
    }

    #[test]
    fn full_grooming_sequence_high_alert() {
        let detector = GroomingDetector::new(true);
        let timeline = make_timeline(vec![
            (EventKind::Flattery, 1000),
            (EventKind::GiftOffer, 2000),
            (EventKind::SecrecyRequest, 3000),
            (EventKind::PhotoRequest, 4000),
            (EventKind::SexualContent, 5000),
        ]);
        let profiler = ContactProfiler::new();

        let signals = detector.analyze(&timeline, "predator", 0, &profiler);
        assert!(!signals.is_empty());

        assert!(
            signals[0].score >= 0.75,
            "Expected high score, got {}",
            signals[0].score
        );
        assert_eq!(signals[0].confidence, Confidence::High);
    }

    #[test]
    fn rapid_escalation_increases_score() {
        let detector = GroomingDetector::new(true);

        let slow = make_timeline(vec![
            (EventKind::Flattery, 0),
            (EventKind::SecrecyRequest, 72 * 3600 * 1000),
            (EventKind::PhotoRequest, 144 * 3600 * 1000),
        ]);

        let fast = make_timeline(vec![
            (EventKind::Flattery, 0),
            (EventKind::SecrecyRequest, 3600 * 1000),
            (EventKind::PhotoRequest, 2 * 3600 * 1000 - 1),
        ]);

        let profiler = ContactProfiler::new();

        let slow_signals = detector.analyze(&slow, "predator", 0, &profiler);
        let fast_signals = detector.analyze(&fast, "predator", 0, &profiler);

        assert!(!slow_signals.is_empty());
        assert!(!fast_signals.is_empty());

        assert!(
            fast_signals[0].score > slow_signals[0].score,
            "Fast ({}) should score higher than slow ({})",
            fast_signals[0].score,
            slow_signals[0].score
        );
    }

    #[test]
    fn child_mode_is_stricter() {
        let child_detector = GroomingDetector::new(true);
        let adult_detector = GroomingDetector::new(false);

        let timeline = make_timeline(vec![
            (EventKind::Flattery, 1000),
            (EventKind::SecrecyRequest, 2000),
        ]);
        let profiler = ContactProfiler::new();

        let child_signals = child_detector.analyze(&timeline, "predator", 0, &profiler);
        let adult_signals = adult_detector.analyze(&timeline, "predator", 0, &profiler);

        let child_score = child_signals.first().map(|s| s.score).unwrap_or(0.0);
        let adult_score = adult_signals.first().map(|s| s.score).unwrap_or(0.0);
        assert!(child_score >= adult_score);
    }

    #[test]
    fn control_stage_detected() {
        let detector = GroomingDetector::new(true);
        let timeline = make_timeline(vec![
            (EventKind::Flattery, 1000),
            (EventKind::SecrecyRequest, 2000),
            (EventKind::PhotoRequest, 3000),
            (EventKind::EmotionalBlackmail, 4000),
        ]);
        let profiler = ContactProfiler::new();

        let signals = detector.analyze(&timeline, "predator", 0, &profiler);
        assert!(!signals.is_empty());

        assert!(signals[0].score >= 0.7);
        assert!(signals[0].explanation.contains("control"));
    }

    #[test]
    fn financial_dependency_stage_classified() {
        let detector = GroomingDetector::new(true);
        let timeline = make_timeline(vec![
            (EventKind::Flattery, 1000),
            (EventKind::GiftOffer, 2000),
            (EventKind::MoneyOffer, 3000),
            (EventKind::SecrecyRequest, 4000),
        ]);
        let profiler = ContactProfiler::new();

        let signals = detector.analyze(&timeline, "predator", 0, &profiler);
        assert!(!signals.is_empty());

        assert!(signals[0].explanation.contains("financial dependency"));
    }

    #[test]
    fn video_call_in_boundary_crossing() {
        let detector = GroomingDetector::new(true);
        let timeline = make_timeline(vec![
            (EventKind::Flattery, 1000),
            (EventKind::VideoCallRequest, 2000),
        ]);
        let profiler = ContactProfiler::new();

        let signals = detector.analyze(&timeline, "predator", 0, &profiler);
        assert!(!signals.is_empty());
        assert!(signals[0].explanation.contains("boundary crossing"));
    }

    #[test]
    fn non_monotonic_stage_timestamps_do_not_overflow() {
        let detector = GroomingDetector::new(false);
        let timeline = make_timeline(vec![
            (EventKind::DebtCreation, 1000),
            (EventKind::LoveBombing, 2000),
        ]);
        let profiler = ContactProfiler::new();

        let signals = detector.analyze(&timeline, "predator", 0, &profiler);
        assert!(
            !signals.is_empty(),
            "Out-of-order stage timestamps should not panic or suppress grooming analysis"
        );
    }

    #[test]
    fn six_stage_max_score() {
        let detector = GroomingDetector::new(true);
        let timeline = make_timeline(vec![
            (EventKind::Flattery, 1000),
            (EventKind::GiftOffer, 2000),
            (EventKind::SecrecyRequest, 3000),
            (EventKind::PhotoRequest, 4000),
            (EventKind::SexualContent, 5000),
            (EventKind::EmotionalBlackmail, 6000),
        ]);
        let profiler = ContactProfiler::new();

        let signals = detector.analyze(&timeline, "predator", 0, &profiler);
        assert!(!signals.is_empty());

        assert!(
            signals[0].score >= 0.95,
            "Full 6-stage grooming should score ≥0.95, got {}",
            signals[0].score
        );
        assert!(signals[0].explanation.contains("6 of 6"));
    }

    #[test]
    fn adult_sender_age_boosts_score() {
        let detector = GroomingDetector::new(true);
        let timeline = make_timeline(vec![
            (EventKind::Flattery, 1000),
            (EventKind::SecrecyRequest, 2000),
        ]);

        let profiler_no_age = ContactProfiler::new();
        let signals_no_age = detector.analyze(&timeline, "predator", 0, &profiler_no_age);

        let mut profiler_adult = ContactProfiler::new();
        profiler_adult.record_event(&ContextEvent {
            event_id: 0,
            timestamp_ms: 500,
            sender_id: "predator".to_string(),
            conversation_id: "conv_1".to_string(),
            kind: EventKind::NormalConversation,
            confidence: 1.0,
        });
        profiler_adult.set_inferred_age("predator", 30);
        let signals_adult = detector.analyze(&timeline, "predator", 0, &profiler_adult);

        assert!(!signals_no_age.is_empty());
        assert!(!signals_adult.is_empty());
        assert!(
            signals_adult[0].score > signals_no_age[0].score,
            "Adult sender ({}) should score higher than unknown age ({})",
            signals_adult[0].score,
            signals_no_age[0].score
        );
    }

    #[test]
    fn mutual_peer_courtship_is_dampened_as_ambiguous() {
        let detector = GroomingDetector::new(true);
        let timeline = make_multi_sender_timeline(vec![
            ("teen_1", EventKind::Flattery, 1_000),
            ("teen_2", EventKind::NormalConversation, 2_000),
            ("teen_1", EventKind::CasualMeetingRequest, 3_000),
        ]);
        let profiler = ContactProfiler::new();

        let signals = detector.analyze(&timeline, "teen_1", 0, &profiler);
        let grooming = signals
            .iter()
            .find(|signal| signal.threat_type == ThreatType::Grooming)
            .expect("expected grooming signal");

        assert!(
            grooming.score <= 0.40,
            "Mutual peer courtship should be dampened below high concern, got {}",
            grooming.score
        );
        assert!(
            grooming
                .explanation
                .contains("Mutual peer-style reciprocity"),
            "Expected ambiguity explanation, got {}",
            grooming.explanation
        );
    }

    #[test]
    fn secrecy_prevents_peer_courtship_dampening() {
        let detector = GroomingDetector::new(true);
        let timeline = make_multi_sender_timeline(vec![
            ("teen_1", EventKind::Flattery, 1_000),
            ("teen_2", EventKind::NormalConversation, 2_000),
            ("teen_1", EventKind::CasualMeetingRequest, 3_000),
            ("teen_1", EventKind::SecrecyRequest, 4_000),
        ]);
        let profiler = ContactProfiler::new();

        let signals = detector.analyze(&timeline, "teen_1", 0, &profiler);
        let grooming = signals
            .iter()
            .find(|signal| signal.threat_type == ThreatType::Grooming)
            .expect("expected grooming signal");

        assert!(
            grooming.score >= 0.60,
            "Secrecy should keep the pattern elevated, got {}",
            grooming.score
        );
        assert!(
            !grooming
                .explanation
                .contains("Mutual peer-style reciprocity"),
            "Higher-risk stages should not receive peer-courtship dampening"
        );
    }

    #[test]
    fn financial_grooming_event_classified() {
        let detector = GroomingDetector::new(true);
        let timeline = make_timeline(vec![
            (EventKind::Flattery, 1000),
            (EventKind::FinancialGrooming, 2000),
        ]);
        let profiler = ContactProfiler::new();

        let signals = detector.analyze(&timeline, "predator", 0, &profiler);
        assert!(!signals.is_empty());
        assert!(signals[0].explanation.contains("financial dependency"));
    }

    #[test]
    fn dependency_before_isolation_ordering() {
        let detector = GroomingDetector::new(true);

        let ordered = make_timeline(vec![
            (EventKind::Flattery, 1000),
            (EventKind::GiftOffer, 2000),
            (EventKind::SecrecyRequest, 3000),
        ]);

        let reversed = make_timeline(vec![
            (EventKind::Flattery, 1000),
            (EventKind::SecrecyRequest, 2000),
            (EventKind::GiftOffer, 3000),
        ]);
        let profiler = ContactProfiler::new();

        let ordered_signals = detector.analyze(&ordered, "predator", 0, &profiler);
        let reversed_signals = detector.analyze(&reversed, "predator", 0, &profiler);

        assert!(!ordered_signals.is_empty());
        assert!(!reversed_signals.is_empty());

        assert!(
            ordered_signals[0].score >= reversed_signals[0].score,
            "Ordered ({}) should score >= reversed ({})",
            ordered_signals[0].score,
            reversed_signals[0].score
        );
    }

    #[test]
    fn repeated_secrecy_escalates() {
        let detector = GroomingDetector::new(true);
        let timeline = make_timeline(vec![
            (EventKind::SecrecyRequest, 1000),
            (EventKind::SecrecyRequest, 2000),
            (EventKind::SecrecyRequest, 3000),
        ]);
        let profiler = ContactProfiler::new();

        let signals = detector.analyze(&timeline, "predator", 0, &profiler);
        let secrecy = signals.iter().find(|s| s.explanation.contains("secrecy"));
        assert!(
            secrecy.is_some(),
            "Expected secrecy escalation, got: {signals:?}"
        );
        assert!(secrecy.unwrap().score >= 0.6);
    }

    #[test]
    fn casual_meeting_alone_low_score() {
        let detector = GroomingDetector::new(true);
        let timeline = make_timeline(vec![(EventKind::CasualMeetingRequest, 1000)]);
        let profiler = ContactProfiler::new();

        let signals = detector.analyze(&timeline, "predator", 0, &profiler);
        let max_score = signals.iter().map(|s| s.score).fold(0.0f32, f32::max);
        assert!(
            max_score < 0.4,
            "Casual meeting alone should be low score, got {}",
            max_score
        );
    }

    #[test]
    fn casual_meeting_with_grooming_context() {
        let detector = GroomingDetector::new(true);
        let timeline = make_timeline(vec![
            (EventKind::Flattery, 1000),
            (EventKind::SecrecyRequest, 2000),
            (EventKind::PersonalInfoRequest, 3000),
            (EventKind::CasualMeetingRequest, 4000),
        ]);
        let profiler = ContactProfiler::new();

        let signals = detector.analyze(&timeline, "predator", 0, &profiler);
        assert!(!signals.is_empty());
        let grooming = signals
            .iter()
            .find(|s| s.threat_type == ThreatType::Grooming);
        assert!(grooming.is_some());
        assert!(
            grooming.unwrap().score >= 0.7,
            "Casual meeting + grooming context should be high, got {}",
            grooming.unwrap().score
        );
    }

    #[test]
    fn minor_sender_no_age_boost() {
        let detector = GroomingDetector::new(true);
        let timeline = make_timeline(vec![
            (EventKind::Flattery, 1000),
            (EventKind::SecrecyRequest, 2000),
        ]);

        let mut profiler = ContactProfiler::new();
        profiler.record_event(&ContextEvent {
            event_id: 0,
            timestamp_ms: 500,
            sender_id: "predator".to_string(),
            conversation_id: "conv_1".to_string(),
            kind: EventKind::NormalConversation,
            confidence: 1.0,
        });
        profiler.set_inferred_age("predator", 15);
        let signals = detector.analyze(&timeline, "predator", 0, &profiler);

        let profiler_no_age = ContactProfiler::new();
        let signals_no_age = detector.analyze(&timeline, "predator", 0, &profiler_no_age);

        assert!(!signals.is_empty());
        assert!(!signals_no_age.is_empty());

        assert!(
            (signals[0].score - signals_no_age[0].score).abs() < 0.01,
            "Minor sender ({}) should have same score as unknown age ({})",
            signals[0].score,
            signals_no_age[0].score
        );
    }

    #[test]
    fn identity_erosion_as_trust_building() {
        let detector = GroomingDetector::new(true);
        let timeline = make_timeline(vec![
            (EventKind::IdentityErosion, 1000),
            (EventKind::SecrecyRequest, 2000),
        ]);
        let profiler = ContactProfiler::new();
        let signals = detector.analyze(&timeline, "predator", 0, &profiler);
        assert!(!signals.is_empty());
        assert!(
            signals[0].explanation.contains("trust building"),
            "IdentityErosion should map to trust building stage, got: {}",
            signals[0].explanation
        );
    }

    #[test]
    fn fake_vulnerability_as_trust_building() {
        let detector = GroomingDetector::new(true);
        let timeline = make_timeline(vec![
            (EventKind::FakeVulnerability, 1000),
            (EventKind::SecrecyRequest, 2000),
        ]);
        let profiler = ContactProfiler::new();
        let signals = detector.analyze(&timeline, "predator", 0, &profiler);
        assert!(!signals.is_empty());
        assert!(
            signals[0].explanation.contains("trust building"),
            "FakeVulnerability should map to trust building stage, got: {}",
            signals[0].explanation
        );
    }

    #[test]
    fn network_poisoning_as_isolation() {
        let detector = GroomingDetector::new(true);
        let timeline = make_timeline(vec![
            (EventKind::Flattery, 1000),
            (EventKind::NetworkPoisoning, 2000),
        ]);
        let profiler = ContactProfiler::new();
        let signals = detector.analyze(&timeline, "predator", 0, &profiler);
        assert!(!signals.is_empty());
        assert!(
            signals[0].explanation.contains("isolation"),
            "NetworkPoisoning should map to isolation stage, got: {}",
            signals[0].explanation
        );
    }

    #[test]
    fn full_advanced_grooming_pipeline() {
        let detector = GroomingDetector::new(true);
        let timeline = make_timeline(vec![
            (EventKind::IdentityErosion, 1000),
            (EventKind::FakeVulnerability, 2000),
            (EventKind::NetworkPoisoning, 3000),
            (EventKind::PlatformSwitch, 4000),
        ]);
        let profiler = ContactProfiler::new();
        let signals = detector.analyze(&timeline, "predator", 0, &profiler);
        assert!(!signals.is_empty());
        let grooming = signals
            .iter()
            .find(|s| s.threat_type == ThreatType::Grooming);
        assert!(grooming.is_some());
        assert!(
            grooming.unwrap().score >= 0.55,
            "4-stage advanced grooming should score >= 0.55, got {}",
            grooming.unwrap().score
        );
    }
}
