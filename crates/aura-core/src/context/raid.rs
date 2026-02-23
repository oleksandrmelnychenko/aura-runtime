use crate::types::{Confidence, DetectionLayer, DetectionSignal, ThreatType};

use super::contact::ContactProfiler;
use super::tracker::ConversationTimeline;

pub struct RaidDetector {
    critical_senders_10min: usize,

    high_senders_30min: usize,
}

impl Default for RaidDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl RaidDetector {
    pub fn new() -> Self {
        Self {
            critical_senders_10min: 5,
            high_senders_30min: 3,
        }
    }

    pub fn analyze(
        &self,
        timeline: &ConversationTimeline,
        now_ms: u64,
        contact_profiler: &ContactProfiler,
    ) -> Vec<DetectionSignal> {
        let mut signals = Vec::new();

        let window_10min = now_ms.saturating_sub(10 * 60 * 1000);
        let hostile_10min = self.count_hostile_senders(timeline, window_10min, contact_profiler);

        if hostile_10min >= self.critical_senders_10min {
            signals.push(DetectionSignal {
                threat_type: ThreatType::Bullying,
                score: 0.95,
                confidence: Confidence::High,
                layer: DetectionLayer::ContextAnalysis,
                explanation: format!(
                    "Coordinated raid detected: {} hostile senders in 10 minutes",
                    hostile_10min
                ),
            });
            return signals;
        }

        let window_30min = now_ms.saturating_sub(30 * 60 * 1000);
        let hostile_30min = self.count_hostile_senders(timeline, window_30min, contact_profiler);

        if hostile_30min >= self.high_senders_30min {
            signals.push(DetectionSignal {
                threat_type: ThreatType::Bullying,
                score: 0.80,
                confidence: Confidence::High,
                layer: DetectionLayer::ContextAnalysis,
                explanation: format!(
                    "Possible coordinated raid: {} hostile senders in 30 minutes",
                    hostile_30min
                ),
            });
        }

        signals
    }

    fn count_hostile_senders(
        &self,
        timeline: &ConversationTimeline,
        since_ms: u64,
        contact_profiler: &ContactProfiler,
    ) -> usize {
        let hostile_senders =
            timeline.unique_senders_matching(since_ms, |event| event.kind.is_bullying_indicator());

        hostile_senders
            .iter()
            .filter(|sender_id| contact_profiler.is_new_contact(sender_id))
            .count()
    }
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

    fn setup_profiler_with_events(events: &[ContextEvent]) -> ContactProfiler {
        let mut profiler = ContactProfiler::new();
        for event in events {
            profiler.record_event(event);
        }
        profiler
    }

    #[test]
    fn no_raid_in_normal_conversation() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![
            make_event("alice", "conv_1", EventKind::NormalConversation, 1000),
            make_event("bob", "conv_1", EventKind::NormalConversation, 2000),
            make_event("carol", "conv_1", EventKind::NormalConversation, 3000),
        ];
        let profiler = setup_profiler_with_events(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = RaidDetector::new();
        let signals = detector.analyze(&timeline, 5000, &profiler);
        assert!(
            signals.is_empty(),
            "Normal conversation should not trigger raid"
        );
    }

    #[test]
    fn no_raid_single_bully() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![
            make_event("bully_1", "conv_1", EventKind::Insult, 1000),
            make_event("bully_1", "conv_1", EventKind::Insult, 2000),
            make_event("bully_1", "conv_1", EventKind::Insult, 3000),
        ];
        let profiler = setup_profiler_with_events(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = RaidDetector::new();
        let signals = detector.analyze(&timeline, 5000, &profiler);
        assert!(signals.is_empty(), "Single bully should not trigger raid");
    }

    #[test]
    fn critical_raid_5_senders_10min() {
        let base_ts = 100_000u64;
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let mut all_events = Vec::new();

        for i in 0..5 {
            let e = make_event(
                &format!("raider_{i}"),
                "conv_1",
                EventKind::Insult,
                base_ts + i as u64 * 60_000,
            );
            all_events.push(e);
        }

        let profiler = setup_profiler_with_events(&all_events);
        for e in all_events {
            timeline.push(e);
        }

        let detector = RaidDetector::new();
        let now = base_ts + 5 * 60_000;
        let signals = detector.analyze(&timeline, now, &profiler);

        assert!(
            !signals.is_empty(),
            "5 hostile senders in 10min should trigger raid"
        );
        assert!(signals[0].score >= 0.9, "Should be critical severity");
        assert!(
            signals[0].explanation.contains("Coordinated raid"),
            "Explanation: {}",
            signals[0].explanation
        );
    }

    #[test]
    fn high_raid_3_senders_30min() {
        let base_ts = 100_000u64;
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let mut all_events = Vec::new();

        for i in 0..3 {
            let e = make_event(
                &format!("raider_{i}"),
                "conv_1",
                EventKind::Insult,
                base_ts + i as u64 * 10 * 60_000,
            );
            all_events.push(e);
        }

        let profiler = setup_profiler_with_events(&all_events);
        for e in all_events {
            timeline.push(e);
        }

        let detector = RaidDetector::new();
        let now = base_ts + 25 * 60_000;
        let signals = detector.analyze(&timeline, now, &profiler);

        assert!(
            !signals.is_empty(),
            "3 hostile senders in 30min should trigger raid"
        );
        assert!(signals[0].score >= 0.7, "Should be high severity");
        assert!(
            signals[0].explanation.contains("Possible coordinated raid"),
            "Explanation: {}",
            signals[0].explanation
        );
    }

    #[test]
    fn established_contacts_not_counted_as_raid() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let mut all_events = Vec::new();

        for i in 0..5 {
            let old_event = make_event(
                &format!("bully_{i}"),
                "conv_1",
                EventKind::NormalConversation,
                0,
            );
            all_events.push(old_event);
        }

        let raid_ts = 3 * 24 * 60 * 60 * 1000u64;
        for i in 0..5 {
            let e = make_event(
                &format!("bully_{i}"),
                "conv_1",
                EventKind::Insult,
                raid_ts + i as u64 * 60_000,
            );
            all_events.push(e);
        }

        let profiler = setup_profiler_with_events(&all_events);
        for e in all_events {
            timeline.push(e);
        }

        let detector = RaidDetector::new();
        let now = raid_ts + 5 * 60_000;
        let signals = detector.analyze(&timeline, now, &profiler);

        assert!(
            signals.is_empty(),
            "Established contacts should not trigger raid: {signals:?}"
        );
    }

    #[test]
    fn mixed_hostile_events_counted() {
        let base_ts = 100_000u64;
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let mut all_events = Vec::new();

        let kinds = [
            EventKind::Insult,
            EventKind::PhysicalThreat,
            EventKind::Denigration,
            EventKind::Mockery,
            EventKind::HarmEncouragement,
        ];

        for (i, kind) in kinds.iter().enumerate() {
            let e = make_event(
                &format!("attacker_{i}"),
                "conv_1",
                kind.clone(),
                base_ts + i as u64 * 60_000,
            );
            all_events.push(e);
        }

        let profiler = setup_profiler_with_events(&all_events);
        for e in all_events {
            timeline.push(e);
        }

        let detector = RaidDetector::new();
        let now = base_ts + 5 * 60_000;
        let signals = detector.analyze(&timeline, now, &profiler);

        assert!(
            !signals.is_empty(),
            "Mixed hostile events from 5 senders should trigger raid"
        );
    }

    #[test]
    fn old_events_outside_window_not_counted() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let mut all_events = Vec::new();

        let old_ts = 0u64;
        for i in 0..5 {
            let e = make_event(
                &format!("raider_{i}"),
                "conv_1",
                EventKind::Insult,
                old_ts + i as u64 * 60_000,
            );
            all_events.push(e);
        }

        let profiler = setup_profiler_with_events(&all_events);
        for e in all_events {
            timeline.push(e);
        }

        let detector = RaidDetector::new();
        let now = 2 * 60 * 60 * 1000;

        let signals = detector.analyze(&timeline, now, &profiler);

        assert!(
            signals.is_empty(),
            "Events outside time window should not trigger raid"
        );
    }

    #[test]
    fn raid_with_some_normal_messages() {
        let base_ts = 100_000u64;
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let mut all_events = Vec::new();

        for i in 0..5 {
            let e = make_event(
                &format!("raider_{i}"),
                "conv_1",
                EventKind::Insult,
                base_ts + i as u64 * 60_000,
            );
            all_events.push(e);
        }

        for i in 0..3 {
            let e = make_event(
                &format!("bystander_{i}"),
                "conv_1",
                EventKind::NormalConversation,
                base_ts + i as u64 * 60_000,
            );
            all_events.push(e);
        }

        let profiler = setup_profiler_with_events(&all_events);
        for e in all_events {
            timeline.push(e);
        }

        let detector = RaidDetector::new();
        let now = base_ts + 5 * 60_000;
        let signals = detector.analyze(&timeline, now, &profiler);

        assert!(
            !signals.is_empty(),
            "Raid should still be detected despite normal messages"
        );
    }
}
