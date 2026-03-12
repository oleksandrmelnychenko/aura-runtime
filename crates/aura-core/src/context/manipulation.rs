use crate::types::{Confidence, DetectionSignal, SignalFamily, ThreatType};

use super::events::EventKind;
use super::tracker::ConversationTimeline;

pub struct ManipulationDetector;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ManipulationTactic {
    Gaslighting,
    GuiltTripping,
    EmotionalBlackmail,
    PeerPressure,
    Isolation,
    Darvo,
    Devaluation,
    BlackmailThreat,
    DareChallenge,
    FalseConsensus,
    NetworkPoisoning,
    FakeVulnerability,
    IdentityErosion,
    ReputationThreat,
    DebtCreation,
}

impl Default for ManipulationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ManipulationDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        window_start: u64,
    ) -> Vec<DetectionSignal> {
        let mut signals = Vec::new();

        if let Some(signal) = self.check_repeated_gaslighting(timeline, sender_id, window_start) {
            signals.push(signal);
        }

        if let Some(signal) = self.check_control_pattern(timeline, sender_id, window_start) {
            signals.push(signal);
        }

        if let Some(signal) =
            self.check_emotional_blackmail_pattern(timeline, sender_id, window_start)
        {
            signals.push(signal);
        }

        if let Some(signal) = self.check_darvo_pattern(timeline, sender_id, window_start) {
            signals.push(signal);
        }

        if let Some(signal) = self.check_love_bomb_devalue_cycle(timeline, sender_id, window_start)
        {
            signals.push(signal);
        }

        if let Some(signal) = self.check_screenshot_blackmail(timeline, sender_id, window_start) {
            signals.push(signal);
        }

        signals
    }

    fn check_repeated_gaslighting(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        window_start: u64,
    ) -> Option<DetectionSignal> {
        let gaslighting_count =
            timeline.count_events(sender_id, &EventKind::Gaslighting, window_start);

        if gaslighting_count >= 3 {
            let score = (0.5 + (gaslighting_count as f32 - 3.0) * 0.1).min(0.9);
            Some(DetectionSignal::context(
                ThreatType::Manipulation,
                score,
                if gaslighting_count >= 5 {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
                SignalFamily::Conversation,
                "conversation.manipulation.repeated_gaslighting",
                format!(
                    "Repeated gaslighting detected: {gaslighting_count} instances of reality-denial from the same sender"
                ),
            ))
        } else {
            None
        }
    }

    fn check_control_pattern(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        window_start: u64,
    ) -> Option<DetectionSignal> {
        let events = timeline.events_from_sender(sender_id, window_start);

        let mut tactics_used = std::collections::HashSet::new();
        let mut total_manipulation = 0usize;

        for event in &events {
            if let Some(tactic) = Self::classify_tactic(&event.kind) {
                tactics_used.insert(tactic);
                total_manipulation += 1;
            }
        }

        let num_tactics = tactics_used.len();

        if num_tactics >= 3 {
            let score = (0.7 + (total_manipulation as f32 * 0.02)).min(0.95);
            Some(DetectionSignal::context(
                ThreatType::Manipulation,
                score,
                Confidence::High,
                SignalFamily::Conversation,
                "conversation.manipulation.multi_tactic_control",
                format!(
                    "Multi-tactic manipulation detected: {} different tactics used ({} total events). \
                     This is a textbook psychological control pattern.",
                    num_tactics, total_manipulation
                ),
            ))
        } else if num_tactics == 2 && total_manipulation >= 4 {
            let score = (0.5 + (total_manipulation as f32 * 0.03)).min(0.8);
            Some(DetectionSignal::context(
                ThreatType::Manipulation,
                score,
                Confidence::Medium,
                SignalFamily::Conversation,
                "conversation.manipulation.multi_tactic_pattern",
                format!(
                    "Manipulation pattern detected: {} different tactics used across {} events",
                    num_tactics, total_manipulation
                ),
            ))
        } else {
            None
        }
    }

    fn check_emotional_blackmail_pattern(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        window_start: u64,
    ) -> Option<DetectionSignal> {
        let blackmail_count =
            timeline.count_events(sender_id, &EventKind::EmotionalBlackmail, window_start);

        if blackmail_count >= 2 {
            let score = (0.6 + (blackmail_count as f32 - 2.0) * 0.1).min(0.9);
            Some(DetectionSignal::context(
                ThreatType::Manipulation,
                score,
                Confidence::High,
                SignalFamily::Conversation,
                "conversation.manipulation.emotional_blackmail",
                format!(
                    "Emotional blackmail pattern detected: sender has used {blackmail_count} \
                     threats of self-harm or abandonment to control the conversation"
                ),
            ))
        } else {
            None
        }
    }

    fn check_darvo_pattern(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        window_start: u64,
    ) -> Option<DetectionSignal> {
        let darvo_count = timeline.count_events(sender_id, &EventKind::Darvo, window_start);

        if darvo_count >= 2 {
            let score = (0.6 + (darvo_count as f32 - 2.0) * 0.1).min(0.85);
            Some(DetectionSignal::context(
                ThreatType::Manipulation,
                score,
                if darvo_count >= 4 {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
                SignalFamily::Conversation,
                "conversation.manipulation.darvo",
                format!(
                    "DARVO pattern detected: sender reversed victim/offender roles {} times",
                    darvo_count
                ),
            ))
        } else {
            None
        }
    }

    fn check_love_bomb_devalue_cycle(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        window_start: u64,
    ) -> Option<DetectionSignal> {
        let events = timeline.events_from_sender(sender_id, window_start);

        let love_count = events
            .iter()
            .filter(|e| e.kind == EventKind::LoveBombing)
            .count();

        let devalue_count = events
            .iter()
            .filter(|e| e.kind == EventKind::Devaluation || e.kind == EventKind::Denigration)
            .count();

        if love_count >= 2 && devalue_count >= 2 {
            let total = love_count + devalue_count;
            let score = (0.7 + (total as f32 - 4.0) * 0.02).min(0.85);
            Some(DetectionSignal::context(
                ThreatType::Manipulation,
                score,
                Confidence::High,
                SignalFamily::Conversation,
                "conversation.manipulation.love_bomb_devalue_cycle",
                format!(
                    "Love-bomb/devalue cycle detected: {} affection + {} devaluation events from same sender. \
                     This creates psychological dependency through intermittent reinforcement.",
                    love_count, devalue_count
                ),
            ))
        } else {
            None
        }
    }

    fn check_screenshot_blackmail(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        window_start: u64,
    ) -> Option<DetectionSignal> {
        let screenshot_count =
            timeline.count_events(sender_id, &EventKind::ScreenshotThreat, window_start);
        let reputation_count =
            timeline.count_events(sender_id, &EventKind::ReputationThreat, window_start);

        if screenshot_count >= 1 && reputation_count >= 1 {
            let score =
                (0.75 + ((screenshot_count + reputation_count) as f32 - 2.0) * 0.05).min(0.92);
            Some(DetectionSignal::context(
                ThreatType::Manipulation,
                score,
                Confidence::High,
                SignalFamily::Conversation,
                "conversation.manipulation.screenshot_reputation_blackmail",
                format!(
                    "Screenshot blackmail with reputation threat detected: {} screenshot signals + {} reputation threats",
                    screenshot_count, reputation_count
                ),
            ))
        } else if screenshot_count >= 2 {
            let score = (0.7 + (screenshot_count as f32 - 2.0) * 0.1).min(0.9);
            Some(DetectionSignal::context(
                ThreatType::Manipulation,
                score,
                if screenshot_count >= 4 {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
                SignalFamily::Conversation,
                "conversation.manipulation.screenshot_blackmail",
                format!(
                    "Screenshot blackmail pattern detected: {} threats to share screenshots/recordings",
                    screenshot_count
                ),
            ))
        } else {
            None
        }
    }

    fn classify_tactic(kind: &EventKind) -> Option<ManipulationTactic> {
        match kind {
            EventKind::Gaslighting => Some(ManipulationTactic::Gaslighting),
            EventKind::GuiltTripping => Some(ManipulationTactic::GuiltTripping),
            EventKind::EmotionalBlackmail => Some(ManipulationTactic::EmotionalBlackmail),
            EventKind::PeerPressure => Some(ManipulationTactic::PeerPressure),
            EventKind::Exclusion => Some(ManipulationTactic::Isolation),
            EventKind::Darvo => Some(ManipulationTactic::Darvo),
            EventKind::Devaluation => Some(ManipulationTactic::Devaluation),
            EventKind::ScreenshotThreat => Some(ManipulationTactic::BlackmailThreat),
            EventKind::DareChallenge => Some(ManipulationTactic::DareChallenge),
            EventKind::FalseConsensus => Some(ManipulationTactic::FalseConsensus),
            EventKind::NetworkPoisoning => Some(ManipulationTactic::NetworkPoisoning),
            EventKind::FakeVulnerability => Some(ManipulationTactic::FakeVulnerability),
            EventKind::IdentityErosion => Some(ManipulationTactic::IdentityErosion),
            EventKind::ReputationThreat => Some(ManipulationTactic::ReputationThreat),
            EventKind::DebtCreation => Some(ManipulationTactic::DebtCreation),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::events::{ContextEvent, EventKind};
    use super::super::tracker::ConversationTimeline;
    use super::*;

    fn make_timeline(events: Vec<(&str, EventKind, u64)>) -> ConversationTimeline {
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
    fn no_manipulation_in_normal_conversation() {
        let detector = ManipulationDetector::new();
        let timeline = make_timeline(vec![
            ("alice", EventKind::NormalConversation, 1000),
            ("alice", EventKind::NormalConversation, 2000),
        ]);
        let signals = detector.analyze(&timeline, "alice", 0);
        assert!(signals.is_empty());
    }

    #[test]
    fn single_gaslighting_not_flagged() {
        let detector = ManipulationDetector::new();
        let timeline = make_timeline(vec![("manipulator", EventKind::Gaslighting, 1000)]);
        let signals = detector.analyze(&timeline, "manipulator", 0);
        assert!(signals.is_empty());
    }

    #[test]
    fn repeated_gaslighting_detected() {
        let detector = ManipulationDetector::new();
        let timeline = make_timeline(vec![
            ("manipulator", EventKind::Gaslighting, 1000),
            ("manipulator", EventKind::Gaslighting, 2000),
            ("manipulator", EventKind::Gaslighting, 3000),
        ]);
        let signals = detector.analyze(&timeline, "manipulator", 0);
        assert!(
            signals
                .iter()
                .any(|s| s.explanation.contains("gaslighting")),
            "Expected gaslighting detection, got: {signals:?}"
        );
    }

    #[test]
    fn multi_tactic_control_pattern() {
        let detector = ManipulationDetector::new();
        let timeline = make_timeline(vec![
            ("abuser", EventKind::Gaslighting, 1000),
            ("abuser", EventKind::GuiltTripping, 2000),
            ("abuser", EventKind::EmotionalBlackmail, 3000),
        ]);
        let signals = detector.analyze(&timeline, "abuser", 0);
        assert!(
            signals
                .iter()
                .any(|s| s.explanation.contains("Multi-tactic")),
            "Expected multi-tactic detection, got: {signals:?}"
        );
        let control = signals
            .iter()
            .find(|s| s.explanation.contains("Multi-tactic"))
            .unwrap();
        assert!(
            control.score >= 0.7,
            "Multi-tactic should score high, got {}",
            control.score
        );
    }

    #[test]
    fn two_tactics_with_frequency() {
        let detector = ManipulationDetector::new();
        let timeline = make_timeline(vec![
            ("manipulator", EventKind::Gaslighting, 1000),
            ("manipulator", EventKind::Gaslighting, 2000),
            ("manipulator", EventKind::GuiltTripping, 3000),
            ("manipulator", EventKind::GuiltTripping, 4000),
        ]);
        let signals = detector.analyze(&timeline, "manipulator", 0);
        assert!(
            signals
                .iter()
                .any(|s| s.explanation.contains("Manipulation pattern")),
            "Expected 2-tactic pattern, got: {signals:?}"
        );
    }

    #[test]
    fn emotional_blackmail_repeated() {
        let detector = ManipulationDetector::new();
        let timeline = make_timeline(vec![
            ("controller", EventKind::EmotionalBlackmail, 1000),
            ("controller", EventKind::EmotionalBlackmail, 2000),
        ]);
        let signals = detector.analyze(&timeline, "controller", 0);
        assert!(
            signals.iter().any(|s| s.explanation.contains("blackmail")),
            "Expected blackmail detection, got: {signals:?}"
        );
    }

    #[test]
    fn different_senders_not_combined() {
        let detector = ManipulationDetector::new();
        let timeline = make_timeline(vec![
            ("person_a", EventKind::Gaslighting, 1000),
            ("person_b", EventKind::Gaslighting, 2000),
            ("person_c", EventKind::Gaslighting, 3000),
        ]);

        let signals = detector.analyze(&timeline, "person_a", 0);
        assert!(signals.is_empty());
    }

    #[test]
    fn darvo_pattern_detected() {
        let detector = ManipulationDetector::new();
        let timeline = make_timeline(vec![
            ("abuser", EventKind::Darvo, 1000),
            ("abuser", EventKind::Darvo, 2000),
        ]);
        let signals = detector.analyze(&timeline, "abuser", 0);
        let darvo = signals.iter().find(|s| s.explanation.contains("DARVO"));
        assert!(darvo.is_some(), "Expected DARVO pattern, got: {signals:?}");
        assert!((darvo.unwrap().score - 0.6).abs() < 0.01);
    }

    #[test]
    fn single_darvo_not_enough() {
        let detector = ManipulationDetector::new();
        let timeline = make_timeline(vec![("abuser", EventKind::Darvo, 1000)]);
        let signals = detector.analyze(&timeline, "abuser", 0);
        let darvo = signals.iter().find(|s| s.explanation.contains("DARVO"));
        assert!(darvo.is_none(), "Single DARVO should not trigger pattern");
    }

    #[test]
    fn love_bomb_devalue_cycle_detected() {
        let detector = ManipulationDetector::new();
        let timeline = make_timeline(vec![
            ("abuser", EventKind::LoveBombing, 1000),
            ("abuser", EventKind::LoveBombing, 2000),
            ("abuser", EventKind::Devaluation, 3000),
            ("abuser", EventKind::Denigration, 4000),
        ]);
        let signals = detector.analyze(&timeline, "abuser", 0);
        let cycle = signals.iter().find(|s| s.explanation.contains("Love-bomb"));
        assert!(
            cycle.is_some(),
            "Expected love-bomb/devalue cycle, got: {signals:?}"
        );
        assert!(cycle.unwrap().score >= 0.7);
    }

    #[test]
    fn love_bomb_only_no_cycle() {
        let detector = ManipulationDetector::new();
        let timeline = make_timeline(vec![
            ("person", EventKind::LoveBombing, 1000),
            ("person", EventKind::LoveBombing, 2000),
            ("person", EventKind::LoveBombing, 3000),
        ]);
        let signals = detector.analyze(&timeline, "person", 0);
        let cycle = signals.iter().find(|s| s.explanation.contains("Love-bomb"));
        assert!(
            cycle.is_none(),
            "Love bombing alone should not trigger cycle"
        );
    }

    #[test]
    fn five_plus_tactics_high_score() {
        let detector = ManipulationDetector::new();
        let timeline = make_timeline(vec![
            ("abuser", EventKind::Gaslighting, 1000),
            ("abuser", EventKind::GuiltTripping, 2000),
            ("abuser", EventKind::EmotionalBlackmail, 3000),
            ("abuser", EventKind::Darvo, 4000),
            ("abuser", EventKind::Devaluation, 5000),
        ]);
        let signals = detector.analyze(&timeline, "abuser", 0);
        let control = signals
            .iter()
            .find(|s| s.explanation.contains("Multi-tactic"));
        assert!(control.is_some(), "Expected multi-tactic, got: {signals:?}");
        assert!(
            control.unwrap().score >= 0.7,
            "5 tactics should have high score, got {}",
            control.unwrap().score
        );
    }

    #[test]
    fn screenshot_blackmail_detected() {
        let detector = ManipulationDetector::new();
        let timeline = make_timeline(vec![
            ("bully", EventKind::ScreenshotThreat, 1000),
            ("bully", EventKind::ScreenshotThreat, 2000),
        ]);
        let signals = detector.analyze(&timeline, "bully", 0);
        let blackmail = signals
            .iter()
            .find(|s| s.explanation.contains("Screenshot blackmail"));
        assert!(
            blackmail.is_some(),
            "Expected screenshot blackmail, got: {signals:?}"
        );
        assert!(blackmail.unwrap().score >= 0.7);
    }

    #[test]
    fn screenshot_plus_reputation_threat_detected_early() {
        let detector = ManipulationDetector::new();
        let timeline = make_timeline(vec![
            ("bully", EventKind::ScreenshotThreat, 1000),
            ("bully", EventKind::ReputationThreat, 2000),
        ]);
        let signals = detector.analyze(&timeline, "bully", 0);
        let blackmail = signals
            .iter()
            .find(|s| s.reason_code == "conversation.manipulation.screenshot_reputation_blackmail");
        assert!(
            blackmail.is_some(),
            "Expected screenshot + reputation blackmail, got: {signals:?}"
        );
        assert!(blackmail.unwrap().score >= 0.75);
    }

    #[test]
    fn single_screenshot_not_blackmail() {
        let detector = ManipulationDetector::new();
        let timeline = make_timeline(vec![("bully", EventKind::ScreenshotThreat, 1000)]);
        let signals = detector.analyze(&timeline, "bully", 0);
        let blackmail = signals
            .iter()
            .find(|s| s.explanation.contains("Screenshot blackmail"));
        assert!(
            blackmail.is_none(),
            "Single screenshot should not trigger blackmail pattern"
        );
    }

    #[test]
    fn dare_as_manipulation_tactic() {
        let detector = ManipulationDetector::new();
        let timeline = make_timeline(vec![
            ("abuser", EventKind::Gaslighting, 1000),
            ("abuser", EventKind::GuiltTripping, 2000),
            ("abuser", EventKind::DareChallenge, 3000),
        ]);
        let signals = detector.analyze(&timeline, "abuser", 0);
        assert!(
            signals
                .iter()
                .any(|s| s.explanation.contains("Multi-tactic")),
            "DareChallenge should count as manipulation tactic, got: {signals:?}"
        );
    }

    #[test]
    fn darvo_classified_as_manipulation() {
        let detector = ManipulationDetector::new();
        let timeline = make_timeline(vec![
            ("abuser", EventKind::Darvo, 1000),
            ("abuser", EventKind::Darvo, 2000),
            ("abuser", EventKind::Darvo, 3000),
        ]);
        let signals = detector.analyze(&timeline, "abuser", 0);
        assert!(
            signals
                .iter()
                .all(|s| s.threat_type == ThreatType::Manipulation),
            "All DARVO signals should be ThreatType::Manipulation"
        );

        let darvo = signals
            .iter()
            .find(|s| s.explanation.contains("DARVO"))
            .unwrap();
        assert!((darvo.score - 0.7).abs() < 0.01);
    }

    #[test]
    fn false_consensus_as_tactic() {
        let detector = ManipulationDetector::new();
        let timeline = make_timeline(vec![
            ("abuser", EventKind::Gaslighting, 1000),
            ("abuser", EventKind::GuiltTripping, 2000),
            ("abuser", EventKind::FalseConsensus, 3000),
        ]);
        let signals = detector.analyze(&timeline, "abuser", 0);
        assert!(
            signals
                .iter()
                .any(|s| s.explanation.contains("Multi-tactic")),
            "FalseConsensus should count as manipulation tactic, got: {signals:?}"
        );
    }

    #[test]
    fn network_poisoning_as_tactic() {
        let detector = ManipulationDetector::new();
        let timeline = make_timeline(vec![
            ("abuser", EventKind::Gaslighting, 1000),
            ("abuser", EventKind::GuiltTripping, 2000),
            ("abuser", EventKind::NetworkPoisoning, 3000),
        ]);
        let signals = detector.analyze(&timeline, "abuser", 0);
        assert!(
            signals
                .iter()
                .any(|s| s.explanation.contains("Multi-tactic")),
            "NetworkPoisoning should count as manipulation tactic, got: {signals:?}"
        );
    }

    #[test]
    fn reputation_threat_as_tactic() {
        let detector = ManipulationDetector::new();
        let timeline = make_timeline(vec![
            ("abuser", EventKind::Gaslighting, 1000),
            ("abuser", EventKind::DebtCreation, 2000),
            ("abuser", EventKind::ReputationThreat, 3000),
        ]);
        let signals = detector.analyze(&timeline, "abuser", 0);
        assert!(
            signals
                .iter()
                .any(|s| s.explanation.contains("Multi-tactic")),
            "ReputationThreat should count as manipulation tactic, got: {signals:?}"
        );
    }

    #[test]
    fn advanced_multi_tactic_combo() {
        let detector = ManipulationDetector::new();
        let timeline = make_timeline(vec![
            ("abuser", EventKind::FalseConsensus, 1000),
            ("abuser", EventKind::DebtCreation, 2000),
            ("abuser", EventKind::ReputationThreat, 3000),
            ("abuser", EventKind::NetworkPoisoning, 4000),
        ]);
        let signals = detector.analyze(&timeline, "abuser", 0);
        let control = signals
            .iter()
            .find(|s| s.explanation.contains("Multi-tactic"));
        assert!(
            control.is_some(),
            "4 advanced tactics should trigger multi-tactic, got: {signals:?}"
        );
        assert!(
            control.unwrap().score >= 0.7,
            "4 tactics should score >= 0.7, got {}",
            control.unwrap().score
        );
    }
}
