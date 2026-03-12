use crate::types::{Confidence, DetectionSignal, SignalFamily, ThreatType};

use super::events::EventKind;
use super::tracker::ConversationTimeline;

pub struct SelfHarmDetector;

impl Default for SelfHarmDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SelfHarmDetector {
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

        if let Some(signal) =
            self.check_hopelessness_accumulation(timeline, sender_id, window_start)
        {
            signals.push(signal);
        }

        if let Some(signal) = self.check_farewell_sequence(timeline, sender_id, window_start) {
            signals.push(signal);
        }

        if let Some(signal) = self.check_bullied_and_hopeless(timeline, sender_id, window_start) {
            signals.push(signal);
        }

        if let Some(signal) = self.check_acute_vs_chronic(timeline, sender_id, window_start) {
            signals.push(signal);
        }

        if let Some(signal) = self.check_protective_factors(timeline, sender_id, window_start) {
            signals.push(signal);
        }

        if let Some(signal) = self.check_contagion_pattern(timeline, window_start) {
            signals.push(signal);
        }

        signals
    }

    fn check_hopelessness_accumulation(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        window_start: u64,
    ) -> Option<DetectionSignal> {
        let hopelessness_count =
            timeline.count_events(sender_id, &EventKind::Hopelessness, window_start);
        let ideation_count =
            timeline.count_events(sender_id, &EventKind::SuicidalIdeation, window_start);

        let combined = hopelessness_count + ideation_count;

        if combined >= 3 {
            let score = (0.7 + (combined as f32 - 3.0) * 0.05).min(0.95);
            Some(DetectionSignal::context(
                ThreatType::SelfHarm,
                score,
                Confidence::High,
                SignalFamily::Conversation,
                "conversation.selfharm.escalation",
                format!(
                    "Self-harm escalation detected: {} expressions of hopelessness/suicidal ideation \
                     across multiple messages. Crisis resources should be prominently displayed.",
                    combined
                ),
            ))
        } else if combined == 2 {
            Some(DetectionSignal::context(
                ThreatType::SelfHarm,
                0.6,
                Confidence::Medium,
                SignalFamily::Conversation,
                "conversation.selfharm.recurring_signals",
                format!(
                    "Recurring self-harm signals: {} expressions of despair detected. Monitoring for escalation.",
                    combined
                ),
            ))
        } else {
            None
        }
    }

    fn check_farewell_sequence(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        window_start: u64,
    ) -> Option<DetectionSignal> {
        let events = timeline.events_from_sender(sender_id, window_start);

        let mut has_hopelessness = false;
        let mut has_ideation = false;
        let mut has_farewell = false;
        let mut farewell_after_darkness = false;

        for event in &events {
            match event.kind {
                EventKind::Hopelessness => has_hopelessness = true,
                EventKind::SuicidalIdeation => has_ideation = true,
                EventKind::FarewellMessage => {
                    has_farewell = true;

                    if has_hopelessness || has_ideation {
                        farewell_after_darkness = true;
                    }
                }
                _ => {}
            }
        }

        if farewell_after_darkness {
            Some(DetectionSignal::context(
                ThreatType::SelfHarm,
                0.95,
                Confidence::High,
                SignalFamily::Conversation,
                "conversation.selfharm.farewell_after_ideation",
                "CRITICAL: Farewell message following expressions of hopelessness/suicidal ideation. \
                     This pattern indicates acute risk. Immediate crisis resources and parent alert needed.",
            ))
        } else if has_farewell && !has_hopelessness && !has_ideation {
            Some(DetectionSignal::context(
                ThreatType::SelfHarm,
                0.6,
                Confidence::Medium,
                SignalFamily::Conversation,
                "conversation.selfharm.farewell_only",
                "Farewell message detected without prior self-harm signals. \
                     May be benign, but crisis resources should be available.",
            ))
        } else {
            None
        }
    }

    fn check_acute_vs_chronic(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        window_start: u64,
    ) -> Option<DetectionSignal> {
        let events: Vec<_> = timeline
            .events_from_sender(sender_id, window_start)
            .into_iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    EventKind::Hopelessness
                        | EventKind::SuicidalIdeation
                        | EventKind::FarewellMessage
                )
            })
            .collect();

        if events.len() < 3 {
            return None;
        }

        let day_ms: u64 = 24 * 60 * 60 * 1000;
        let last_ts = events.last().unwrap().timestamp_ms;
        let recent_count = events
            .iter()
            .filter(|e| e.timestamp_ms >= last_ts.saturating_sub(day_ms))
            .count();

        if recent_count >= 3 {
            return Some(DetectionSignal::context(
                ThreatType::SelfHarm,
                0.85,
                Confidence::High,
                SignalFamily::Conversation,
                "conversation.selfharm.acute_crisis",
                format!(
                    "ACUTE self-harm crisis: {} self-harm signals within 24 hours. Immediate crisis resources needed.",
                    recent_count
                ),
            ));
        }

        let mut days: Vec<u64> = events.iter().map(|e| e.timestamp_ms / day_ms).collect();
        days.sort();
        days.dedup();

        if days.len() >= 3 {
            Some(DetectionSignal::context(
                ThreatType::SelfHarm,
                0.75,
                Confidence::High,
                SignalFamily::Conversation,
                "conversation.selfharm.chronic_pattern",
                format!(
                    "Chronic self-harm pattern: self-harm signals across {} distinct days. Sustained risk — parent alert recommended.",
                    days.len()
                ),
            ))
        } else {
            None
        }
    }

    fn check_protective_factors(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        window_start: u64,
    ) -> Option<DetectionSignal> {
        let events = timeline.events_from_sender(sender_id, window_start);

        let mut last_hopelessness_ts: Option<u64> = None;
        let mut positive_after_hopelessness = 0usize;

        for event in &events {
            match event.kind {
                EventKind::Hopelessness | EventKind::SuicidalIdeation => {
                    last_hopelessness_ts = Some(event.timestamp_ms);
                }
                EventKind::NormalConversation | EventKind::DefenseOfVictim => {
                    if last_hopelessness_ts.is_some() {
                        positive_after_hopelessness += 1;
                    }
                }
                _ => {}
            }
        }

        if last_hopelessness_ts.is_some() && positive_after_hopelessness >= 3 {
            Some(DetectionSignal::context(
                ThreatType::SelfHarm,
                -0.1,
                Confidence::Low,
                SignalFamily::Conversation,
                "conversation.selfharm.protective_factor",
                format!(
                    "Protective factor: {} positive interactions after hopelessness expression. \
                     Risk slightly reduced but continued monitoring recommended.",
                    positive_after_hopelessness
                ),
            ))
        } else {
            None
        }
    }

    fn check_contagion_pattern(
        &self,
        timeline: &ConversationTimeline,
        window_start: u64,
    ) -> Option<DetectionSignal> {
        let two_days_ms: u64 = 48 * 60 * 60 * 1000;
        let events = timeline.events_since(window_start);

        let self_harm_events: Vec<_> = events
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    EventKind::Hopelessness | EventKind::SuicidalIdeation
                )
            })
            .collect();

        if self_harm_events.len() < 2 {
            return None;
        }

        let mut senders_in_window = std::collections::HashSet::new();
        for event in &self_harm_events {
            let window_events: Vec<_> = self_harm_events
                .iter()
                .filter(|e| {
                    e.timestamp_ms >= event.timestamp_ms.saturating_sub(two_days_ms)
                        && e.timestamp_ms <= event.timestamp_ms + two_days_ms
                })
                .collect();

            for e in &window_events {
                senders_in_window.insert(e.sender_id.as_str());
            }

            if senders_in_window.len() >= 2 {
                return Some(DetectionSignal::context(
                    ThreatType::SelfHarm,
                    0.7,
                    Confidence::Medium,
                    SignalFamily::Abuse,
                    "abuse.selfharm.contagion",
                    format!(
                        "Self-harm contagion risk: {} different people expressed hopelessness within 48 hours. \
                         Group-level crisis intervention may be needed.",
                        senders_in_window.len()
                    ),
                ));
            }

            senders_in_window.clear();
        }

        None
    }

    fn check_bullied_and_hopeless(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        window_start: u64,
    ) -> Option<DetectionSignal> {
        let events = timeline.events_since(window_start);

        let bullying_received = events
            .iter()
            .filter(|e| e.sender_id != sender_id && e.kind.is_bullying_indicator())
            .count();

        let self_harm_expressed = events
            .iter()
            .filter(|e| {
                e.sender_id == sender_id
                    && matches!(
                        e.kind,
                        EventKind::Hopelessness
                            | EventKind::SuicidalIdeation
                            | EventKind::FarewellMessage
                    )
            })
            .count();

        if bullying_received >= 2 && self_harm_expressed >= 1 {
            let score = (0.7 + (bullying_received as f32 * 0.05)).min(0.9);
            Some(DetectionSignal::context(
                ThreatType::SelfHarm,
                score,
                Confidence::High,
                SignalFamily::Conversation,
                "conversation.selfharm.bullying_pathway",
                format!(
                    "Bullying-to-self-harm pathway detected: child received {} bullying events \
                     and expressed {} self-harm signals. This combination requires urgent attention.",
                    bullying_received, self_harm_expressed
                ),
            ))
        } else {
            None
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
    fn no_signals_for_normal_conversation() {
        let detector = SelfHarmDetector::new();
        let timeline = make_timeline(vec![
            ("child", EventKind::NormalConversation, 1000),
            ("child", EventKind::NormalConversation, 2000),
        ]);
        let signals = detector.analyze(&timeline, "child", 0);
        assert!(signals.is_empty());
    }

    #[test]
    fn single_hopelessness_not_escalation() {
        let detector = SelfHarmDetector::new();
        let timeline = make_timeline(vec![("child", EventKind::Hopelessness, 1000)]);
        let signals = detector.analyze(&timeline, "child", 0);

        assert!(
            !signals.iter().any(|s| s.explanation.contains("escalation")),
            "Single event should not trigger escalation"
        );
    }

    #[test]
    fn accumulating_hopelessness_detected() {
        let detector = SelfHarmDetector::new();
        let day = 24 * 3600 * 1000;
        let timeline = make_timeline(vec![
            ("child", EventKind::Hopelessness, 0),
            ("child", EventKind::Hopelessness, day),
            ("child", EventKind::SuicidalIdeation, 2 * day),
        ]);
        let signals = detector.analyze(&timeline, "child", 0);
        assert!(
            signals.iter().any(|s| s.explanation.contains("escalation")),
            "Expected escalation detection, got: {signals:?}"
        );
    }

    #[test]
    fn farewell_after_hopelessness_is_critical() {
        let detector = SelfHarmDetector::new();
        let day = 24 * 3600 * 1000;
        let timeline = make_timeline(vec![
            ("child", EventKind::Hopelessness, 0),
            ("child", EventKind::SuicidalIdeation, day),
            ("child", EventKind::FarewellMessage, 2 * day),
        ]);
        let signals = detector.analyze(&timeline, "child", 0);
        let critical = signals.iter().find(|s| s.explanation.contains("CRITICAL"));
        assert!(
            critical.is_some(),
            "Expected CRITICAL farewell sequence, got: {signals:?}"
        );
        assert!(critical.unwrap().score >= 0.9);
    }

    #[test]
    fn farewell_alone_is_moderate() {
        let detector = SelfHarmDetector::new();
        let timeline = make_timeline(vec![
            ("child", EventKind::NormalConversation, 1000),
            ("child", EventKind::FarewellMessage, 2000),
        ]);
        let signals = detector.analyze(&timeline, "child", 0);
        let farewell = signals.iter().find(|s| s.explanation.contains("Farewell"));
        assert!(farewell.is_some());

        assert!(farewell.unwrap().score < 0.8);
    }

    #[test]
    fn bullied_and_hopeless_pathway() {
        let detector = SelfHarmDetector::new();
        let timeline = make_timeline(vec![
            ("bully_1", EventKind::Insult, 1000),
            ("bully_2", EventKind::Denigration, 2000),
            ("child", EventKind::Hopelessness, 3000),
        ]);
        let signals = detector.analyze(&timeline, "child", 0);
        assert!(
            signals
                .iter()
                .any(|s| s.explanation.contains("Bullying-to-self-harm")),
            "Expected bullying-to-self-harm pathway, got: {signals:?}"
        );
    }

    #[test]
    fn bullying_without_hopelessness_no_pathway() {
        let detector = SelfHarmDetector::new();
        let timeline = make_timeline(vec![
            ("bully_1", EventKind::Insult, 1000),
            ("bully_2", EventKind::Denigration, 2000),
            ("child", EventKind::NormalConversation, 3000),
        ]);
        let signals = detector.analyze(&timeline, "child", 0);
        assert!(
            !signals
                .iter()
                .any(|s| s.explanation.contains("Bullying-to-self-harm")),
            "Should not detect pathway without self-harm expression"
        );
    }

    #[test]
    fn child_hopelessness_without_bullying_no_pathway() {
        let detector = SelfHarmDetector::new();
        let timeline = make_timeline(vec![
            ("friend", EventKind::NormalConversation, 1000),
            ("child", EventKind::Hopelessness, 2000),
        ]);
        let signals = detector.analyze(&timeline, "child", 0);
        assert!(!signals
            .iter()
            .any(|s| s.explanation.contains("Bullying-to-self-harm")),);
    }

    #[test]
    fn acute_crisis_detected() {
        let detector = SelfHarmDetector::new();
        let hour = 3600 * 1000u64;
        let timeline = make_timeline(vec![
            ("child", EventKind::Hopelessness, 0),
            ("child", EventKind::SuicidalIdeation, hour),
            ("child", EventKind::Hopelessness, 2 * hour),
        ]);
        let signals = detector.analyze(&timeline, "child", 0);
        let acute = signals.iter().find(|s| s.explanation.contains("ACUTE"));
        assert!(acute.is_some(), "Expected acute crisis, got: {signals:?}");
        assert!((acute.unwrap().score - 0.85).abs() < 0.01);
    }

    #[test]
    fn chronic_pattern_across_days() {
        let detector = SelfHarmDetector::new();
        let day = 24 * 3600 * 1000u64;
        let timeline = make_timeline(vec![
            ("child", EventKind::Hopelessness, 0),
            ("child", EventKind::Hopelessness, 2 * day),
            ("child", EventKind::Hopelessness, 5 * day),
        ]);
        let signals = detector.analyze(&timeline, "child", 0);
        let chronic = signals.iter().find(|s| s.explanation.contains("Chronic"));
        assert!(
            chronic.is_some(),
            "Expected chronic pattern, got: {signals:?}"
        );
        assert!((chronic.unwrap().score - 0.75).abs() < 0.01);
    }

    #[test]
    fn protective_factors_reduce_risk() {
        let detector = SelfHarmDetector::new();
        let timeline = make_timeline(vec![
            ("child", EventKind::Hopelessness, 1000),
            ("child", EventKind::NormalConversation, 2000),
            ("child", EventKind::NormalConversation, 3000),
            ("child", EventKind::NormalConversation, 4000),
        ]);
        let signals = detector.analyze(&timeline, "child", 0);
        let protective = signals
            .iter()
            .find(|s| s.explanation.contains("Protective"));
        assert!(
            protective.is_some(),
            "Expected protective factor, got: {signals:?}"
        );
        assert!(
            protective.unwrap().score < 0.0,
            "Protective factor should have negative score"
        );
    }

    #[test]
    fn contagion_two_senders() {
        let detector = SelfHarmDetector::new();
        let hour = 3600 * 1000u64;
        let timeline = make_timeline(vec![
            ("teen_a", EventKind::Hopelessness, 0),
            ("teen_b", EventKind::Hopelessness, 2 * hour),
        ]);
        let signals = detector.analyze(&timeline, "teen_a", 0);
        let contagion = signals.iter().find(|s| s.explanation.contains("contagion"));
        assert!(
            contagion.is_some(),
            "Expected contagion detection, got: {signals:?}"
        );
        assert!((contagion.unwrap().score - 0.7).abs() < 0.01);
    }

    #[test]
    fn no_contagion_single_sender() {
        let detector = SelfHarmDetector::new();
        let hour = 3600 * 1000u64;
        let timeline = make_timeline(vec![
            ("child", EventKind::Hopelessness, 0),
            ("child", EventKind::Hopelessness, hour),
        ]);
        let signals = detector.analyze(&timeline, "child", 0);
        let contagion = signals.iter().find(|s| s.explanation.contains("contagion"));
        assert!(
            contagion.is_none(),
            "Single sender should not trigger contagion"
        );
    }

    #[test]
    fn no_protective_without_enough_positive() {
        let detector = SelfHarmDetector::new();
        let timeline = make_timeline(vec![
            ("child", EventKind::Hopelessness, 1000),
            ("child", EventKind::NormalConversation, 2000),
        ]);
        let signals = detector.analyze(&timeline, "child", 0);
        let protective = signals
            .iter()
            .find(|s| s.explanation.contains("Protective"));
        assert!(
            protective.is_none(),
            "Not enough positive events for protective factor"
        );
    }
}
