use crate::types::{Confidence, DetectionSignal, SignalFamily, ThreatType};

use super::events::EventKind;
use super::tracker::ConversationTimeline;

pub struct BullyingDetector;

struct BullyingThresholds {
    repeated_min_count: usize,

    pileon_min_senders: usize,

    pileon_window_ms: u64,

    repeated_window_ms: u64,
}

impl Default for BullyingThresholds {
    fn default() -> Self {
        Self {
            repeated_min_count: 3,
            pileon_min_senders: 3,
            pileon_window_ms: 24 * 60 * 60 * 1000,

            repeated_window_ms: 7 * 24 * 60 * 60 * 1000,
        }
    }
}

impl Default for BullyingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BullyingDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(
        &self,
        timeline: &ConversationTimeline,
        latest_sender_id: &str,
        window_start: u64,
    ) -> Vec<DetectionSignal> {
        let mut signals = Vec::new();
        let thresholds = BullyingThresholds::default();

        if let Some(signal) =
            self.check_repeated_bullying(timeline, latest_sender_id, window_start, &thresholds)
        {
            signals.push(signal);
        }

        if let Some(signal) = self.check_pile_on(timeline, window_start, &thresholds) {
            signals.push(signal);
        }

        if let Some(signal) = self.check_escalation(timeline, latest_sender_id, window_start) {
            signals.push(signal);
        }

        if let Some(signal) = self.check_isolation(timeline, window_start) {
            signals.push(signal);
        }

        if let Some(signal) =
            self.check_sustained_harassment(timeline, latest_sender_id, window_start)
        {
            signals.push(signal);
        }

        if let Some(signal) = self.check_target_isolation(timeline, window_start) {
            signals.push(signal);
        }

        if let Some(signal) = self.check_bystander_silence(timeline, window_start) {
            signals.push(signal);
        }

        signals
    }

    fn check_repeated_bullying(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        window_start: u64,
        thresholds: &BullyingThresholds,
    ) -> Option<DetectionSignal> {
        let since = window_start.max(
            timeline
                .all_events()
                .last()
                .map(|e| e.timestamp_ms.saturating_sub(thresholds.repeated_window_ms))
                .unwrap_or(0),
        );

        let bullying_count = timeline.count_matching(since, |e| {
            e.sender_id == sender_id && e.kind.is_bullying_indicator()
        });

        if bullying_count >= thresholds.repeated_min_count {
            let score = calculate_repeated_score(bullying_count);
            Some(DetectionSignal::context(
                ThreatType::Bullying,
                score,
                if bullying_count >= 5 {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
                SignalFamily::Conversation,
                "conversation.bullying.repeated",
                format!(
                    "Repeated bullying detected: {bullying_count} hostile messages from the same sender in the past week"
                ),
            ))
        } else {
            None
        }
    }

    fn check_pile_on(
        &self,
        timeline: &ConversationTimeline,
        window_start: u64,
        thresholds: &BullyingThresholds,
    ) -> Option<DetectionSignal> {
        let since = window_start.max(
            timeline
                .all_events()
                .last()
                .map(|e| e.timestamp_ms.saturating_sub(thresholds.pileon_window_ms))
                .unwrap_or(0),
        );

        let bully_senders =
            timeline.unique_senders_matching(since, |e| e.kind.is_bullying_indicator());

        if bully_senders.len() >= thresholds.pileon_min_senders {
            let score = calculate_pileon_score(bully_senders.len());
            Some(DetectionSignal::context(
                ThreatType::Bullying,
                score,
                Confidence::High,
                SignalFamily::Abuse,
                "abuse.bullying.pile_on",
                format!(
                    "Group bullying detected: {} different people sent hostile messages in the past 24 hours",
                    bully_senders.len()
                ),
            ))
        } else {
            None
        }
    }

    fn check_escalation(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        window_start: u64,
    ) -> Option<DetectionSignal> {
        let events: Vec<_> = timeline
            .events_from_sender(sender_id, window_start)
            .into_iter()
            .filter(|e| e.kind.is_bullying_indicator())
            .collect();

        if events.len() < 3 {
            return None;
        }

        let mid = events.len() / 2;
        let early_severity: f32 =
            events[..mid].iter().map(|e| e.kind.severity()).sum::<f32>() / mid as f32;
        let late_severity: f32 = events[mid..].iter().map(|e| e.kind.severity()).sum::<f32>()
            / (events.len() - mid) as f32;

        if late_severity > early_severity + 0.15 {
            let score = 0.6 + (late_severity - early_severity).min(0.3);
            Some(DetectionSignal::context(
                ThreatType::Bullying,
                score,
                Confidence::Medium,
                SignalFamily::Conversation,
                "conversation.bullying.escalation",
                format!(
                    "Escalating bullying detected: hostility increasing over time (severity {early_severity:.2} → {late_severity:.2})"
                ),
            ))
        } else {
            None
        }
    }

    fn check_sustained_harassment(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        window_start: u64,
    ) -> Option<DetectionSignal> {
        let events: Vec<_> = timeline
            .events_from_sender(sender_id, window_start)
            .into_iter()
            .filter(|e| e.kind.is_bullying_indicator())
            .collect();

        if events.is_empty() {
            return None;
        }

        let day_ms: u64 = 24 * 60 * 60 * 1000;
        let mut days: Vec<u64> = events.iter().map(|e| e.timestamp_ms / day_ms).collect();
        days.sort();
        days.dedup();

        if days.len() >= 3 {
            let score = match days.len() {
                3 => 0.65,
                4 => 0.75,
                _ => 0.85,
            };
            Some(DetectionSignal::context(
                ThreatType::Bullying,
                score,
                if days.len() >= 5 {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
                SignalFamily::Conversation,
                "conversation.bullying.sustained_harassment",
                format!(
                    "Sustained harassment: same sender bullied on {} distinct days",
                    days.len()
                ),
            ))
        } else {
            None
        }
    }

    fn check_target_isolation(
        &self,
        timeline: &ConversationTimeline,
        window_start: u64,
    ) -> Option<DetectionSignal> {
        let exclusion_count =
            timeline.count_matching(window_start, |e| e.kind == EventKind::Exclusion);

        let denigration_senders =
            timeline.unique_senders_matching(window_start, |e| e.kind == EventKind::Denigration);

        if exclusion_count >= 1 && denigration_senders.len() >= 2 {
            Some(DetectionSignal::context(
                ThreatType::Bullying,
                0.7,
                Confidence::High,
                SignalFamily::Conversation,
                "conversation.bullying.target_isolation",
                format!(
                    "Target isolation: exclusion + denigration from {} different senders",
                    denigration_senders.len()
                ),
            ))
        } else {
            None
        }
    }

    fn check_bystander_silence(
        &self,
        timeline: &ConversationTimeline,
        window_start: u64,
    ) -> Option<DetectionSignal> {
        let bullying_count =
            timeline.count_matching(window_start, |e| e.kind.is_bullying_indicator());

        let defense_count =
            timeline.count_matching(window_start, |e| e.kind == EventKind::DefenseOfVictim);

        let bully_senders =
            timeline.unique_senders_matching(window_start, |e| e.kind.is_bullying_indicator());

        if bullying_count >= 5 && defense_count == 0 && bully_senders.len() >= 2 {
            Some(DetectionSignal::context(
                ThreatType::Bullying,
                0.5,
                Confidence::Low,
                SignalFamily::Abuse,
                "abuse.bullying.bystander_silence",
                format!(
                    "Bystander silence: {} bullying events from {} senders with no defense observed",
                    bullying_count,
                    bully_senders.len()
                ),
            ))
        } else {
            None
        }
    }

    fn check_isolation(
        &self,
        timeline: &ConversationTimeline,
        window_start: u64,
    ) -> Option<DetectionSignal> {
        let exclusion_count =
            timeline.count_matching(window_start, |e| e.kind == EventKind::Exclusion);

        if exclusion_count >= 2 {
            let senders =
                timeline.unique_senders_matching(window_start, |e| e.kind == EventKind::Exclusion);
            let score = 0.6 + (senders.len() as f32 * 0.1).min(0.3);

            Some(DetectionSignal::context(
                ThreatType::Bullying,
                score,
                if senders.len() >= 2 {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
                SignalFamily::Conversation,
                "conversation.bullying.isolation",
                format!(
                    "Isolation pattern detected: {} exclusion attempts from {} different people",
                    exclusion_count,
                    senders.len()
                ),
            ))
        } else {
            None
        }
    }
}

fn calculate_repeated_score(count: usize) -> f32 {
    match count {
        0..=2 => 0.0,
        3 => 0.5,
        4 => 0.6,
        5 => 0.7,
        6..=9 => 0.8,
        _ => 0.9,
    }
}

fn calculate_pileon_score(num_senders: usize) -> f32 {
    match num_senders {
        0..=2 => 0.0,
        3 => 0.7,
        4 => 0.8,
        _ => 0.9,
    }
}

#[cfg(test)]
mod tests {
    use super::super::events::{ContextEvent, EventKind};
    use super::super::tracker::ConversationTimeline;
    use super::*;

    fn make_timeline_with_senders(events: Vec<(&str, EventKind, u64)>) -> ConversationTimeline {
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
    fn no_bullying_in_normal_conversation() {
        let detector = BullyingDetector::new();
        let timeline = make_timeline_with_senders(vec![
            ("alice", EventKind::NormalConversation, 1000),
            ("bob", EventKind::NormalConversation, 2000),
        ]);

        let signals = detector.analyze(&timeline, "alice", 0);
        assert!(signals.is_empty());
    }

    #[test]
    fn single_insult_not_bullying() {
        let detector = BullyingDetector::new();
        let timeline = make_timeline_with_senders(vec![("bully", EventKind::Insult, 1000)]);

        let signals = detector.analyze(&timeline, "bully", 0);
        assert!(signals.is_empty());
    }

    #[test]
    fn repeated_insults_is_bullying() {
        let detector = BullyingDetector::new();
        let timeline = make_timeline_with_senders(vec![
            ("bully", EventKind::Insult, 1000),
            ("bully", EventKind::Denigration, 2000),
            ("bully", EventKind::Mockery, 3000),
        ]);

        let signals = detector.analyze(&timeline, "bully", 0);
        assert!(!signals.is_empty());

        let repeated = signals
            .iter()
            .find(|s| s.explanation.contains("Repeated bullying"));
        assert!(repeated.is_some());
        assert!(repeated.unwrap().score >= 0.5);
    }

    #[test]
    fn pile_on_from_multiple_senders() {
        let detector = BullyingDetector::new();
        let now = 100_000;
        let timeline = make_timeline_with_senders(vec![
            ("bully_1", EventKind::Insult, now - 1000),
            ("bully_2", EventKind::Denigration, now - 500),
            ("bully_3", EventKind::Mockery, now),
        ]);

        let signals = detector.analyze(&timeline, "bully_3", 0);
        let pileon = signals
            .iter()
            .find(|s| s.explanation.contains("Group bullying"));
        assert!(
            pileon.is_some(),
            "Expected pile-on detection, got: {signals:?}"
        );
        assert!(pileon.unwrap().score >= 0.7);
    }

    #[test]
    fn escalation_detected() {
        let detector = BullyingDetector::new();
        let timeline = make_timeline_with_senders(vec![
            ("bully", EventKind::Mockery, 1000),
            ("bully", EventKind::Mockery, 2000),
            ("bully", EventKind::HarmEncouragement, 3000),
            ("bully", EventKind::PhysicalThreat, 4000),
        ]);

        let signals = detector.analyze(&timeline, "bully", 0);
        let escalation = signals
            .iter()
            .find(|s| s.explanation.contains("Escalating"));
        assert!(
            escalation.is_some(),
            "Expected escalation detection, got: {signals:?}"
        );
    }

    #[test]
    fn isolation_pattern_detected() {
        let detector = BullyingDetector::new();
        let timeline = make_timeline_with_senders(vec![
            ("person_1", EventKind::Exclusion, 1000),
            ("person_2", EventKind::Exclusion, 2000),
        ]);

        let signals = detector.analyze(&timeline, "person_2", 0);
        let isolation = signals.iter().find(|s| s.explanation.contains("Isolation"));
        assert!(
            isolation.is_some(),
            "Expected isolation detection, got: {signals:?}"
        );
    }

    #[test]
    fn many_repeated_insults_high_score() {
        let detector = BullyingDetector::new();
        let timeline = make_timeline_with_senders(vec![
            ("bully", EventKind::Insult, 1000),
            ("bully", EventKind::Insult, 2000),
            ("bully", EventKind::Denigration, 3000),
            ("bully", EventKind::Mockery, 4000),
            ("bully", EventKind::Insult, 5000),
            ("bully", EventKind::PhysicalThreat, 6000),
        ]);

        let signals = detector.analyze(&timeline, "bully", 0);
        let repeated = signals
            .iter()
            .find(|s| s.explanation.contains("Repeated bullying"));
        assert!(repeated.is_some());
        assert!(repeated.unwrap().score >= 0.7);
    }

    #[test]
    fn sustained_harassment_3_days() {
        let detector = BullyingDetector::new();
        let day = 24 * 60 * 60 * 1000u64;
        let timeline = make_timeline_with_senders(vec![
            ("bully", EventKind::Insult, 0),
            ("bully", EventKind::Insult, day),
            ("bully", EventKind::Insult, 2 * day),
        ]);

        let signals = detector.analyze(&timeline, "bully", 0);
        let sustained = signals
            .iter()
            .find(|s| s.explanation.contains("Sustained harassment"));
        assert!(
            sustained.is_some(),
            "Expected sustained harassment on 3 days, got: {signals:?}"
        );
        assert!((sustained.unwrap().score - 0.65).abs() < 0.01);
    }

    #[test]
    fn sustained_harassment_5_days_high_score() {
        let detector = BullyingDetector::new();
        let day = 24 * 60 * 60 * 1000u64;
        let timeline = make_timeline_with_senders(vec![
            ("bully", EventKind::Insult, 0),
            ("bully", EventKind::Denigration, day),
            ("bully", EventKind::Mockery, 2 * day),
            ("bully", EventKind::Insult, 3 * day),
            ("bully", EventKind::Insult, 4 * day),
        ]);

        let signals = detector.analyze(&timeline, "bully", 0);
        let sustained = signals
            .iter()
            .find(|s| s.explanation.contains("Sustained harassment"));
        assert!(sustained.is_some());
        assert!(
            sustained.unwrap().score >= 0.85,
            "5-day sustained should score ≥0.85, got {}",
            sustained.unwrap().score
        );
        assert_eq!(sustained.unwrap().confidence, Confidence::High);
    }

    #[test]
    fn same_day_not_sustained() {
        let detector = BullyingDetector::new();

        let timeline = make_timeline_with_senders(vec![
            ("bully", EventKind::Insult, 1000),
            ("bully", EventKind::Insult, 2000),
            ("bully", EventKind::Insult, 3000),
        ]);

        let signals = detector.analyze(&timeline, "bully", 0);
        let sustained = signals
            .iter()
            .find(|s| s.explanation.contains("Sustained harassment"));
        assert!(
            sustained.is_none(),
            "Same-day insults should not be sustained harassment"
        );
    }

    #[test]
    fn target_isolation_exclusion_plus_denigration() {
        let detector = BullyingDetector::new();
        let timeline = make_timeline_with_senders(vec![
            ("bully_1", EventKind::Exclusion, 1000),
            ("bully_2", EventKind::Denigration, 2000),
            ("bully_3", EventKind::Denigration, 3000),
        ]);

        let signals = detector.analyze(&timeline, "bully_3", 0);
        let isolation = signals
            .iter()
            .find(|s| s.explanation.contains("Target isolation"));
        assert!(
            isolation.is_some(),
            "Expected target isolation, got: {signals:?}"
        );
        assert!((isolation.unwrap().score - 0.7).abs() < 0.01);
    }

    #[test]
    fn exclusion_alone_not_target_isolation() {
        let detector = BullyingDetector::new();

        let timeline = make_timeline_with_senders(vec![
            ("bully_1", EventKind::Exclusion, 1000),
            ("bully_1", EventKind::Exclusion, 2000),
        ]);

        let signals = detector.analyze(&timeline, "bully_1", 0);
        let target_isolation = signals
            .iter()
            .find(|s| s.explanation.contains("Target isolation"));
        assert!(
            target_isolation.is_none(),
            "Exclusion alone should not trigger target isolation"
        );
    }

    #[test]
    fn bystander_silence_detected() {
        let detector = BullyingDetector::new();
        let timeline = make_timeline_with_senders(vec![
            ("bully_1", EventKind::Insult, 1000),
            ("bully_1", EventKind::Denigration, 2000),
            ("bully_2", EventKind::Insult, 3000),
            ("bully_2", EventKind::Mockery, 4000),
            ("bully_1", EventKind::Insult, 5000),
        ]);

        let signals = detector.analyze(&timeline, "bully_1", 0);
        let bystander = signals
            .iter()
            .find(|s| s.explanation.contains("Bystander silence"));
        assert!(
            bystander.is_some(),
            "Expected bystander silence, got: {signals:?}"
        );
        assert!((bystander.unwrap().score - 0.5).abs() < 0.01);
    }

    #[test]
    fn defense_present_no_bystander_silence() {
        let detector = BullyingDetector::new();
        let timeline = make_timeline_with_senders(vec![
            ("bully_1", EventKind::Insult, 1000),
            ("bully_1", EventKind::Denigration, 2000),
            ("bully_2", EventKind::Insult, 3000),
            ("bully_2", EventKind::Mockery, 4000),
            ("bully_1", EventKind::Insult, 5000),
            ("defender", EventKind::DefenseOfVictim, 6000),
        ]);

        let signals = detector.analyze(&timeline, "bully_1", 0);
        let bystander = signals
            .iter()
            .find(|s| s.explanation.contains("Bystander silence"));
        assert!(
            bystander.is_none(),
            "Defense present → no bystander silence signal"
        );
    }

    #[test]
    fn single_bully_no_bystander_silence() {
        let detector = BullyingDetector::new();
        let timeline = make_timeline_with_senders(vec![
            ("bully_1", EventKind::Insult, 1000),
            ("bully_1", EventKind::Denigration, 2000),
            ("bully_1", EventKind::Insult, 3000),
            ("bully_1", EventKind::Mockery, 4000),
            ("bully_1", EventKind::Insult, 5000),
        ]);

        let signals = detector.analyze(&timeline, "bully_1", 0);
        let bystander = signals
            .iter()
            .find(|s| s.explanation.contains("Bystander silence"));
        assert!(
            bystander.is_none(),
            "Single bully should not trigger bystander silence (needs ≥2 senders)"
        );
    }
}
