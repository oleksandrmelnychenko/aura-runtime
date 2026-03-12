use crate::types::{Confidence, DetectionSignal, SignalFamily, ThreatType};

use super::tracker::ConversationTimeline;

pub struct TimingAnalyzer;

pub struct TimingSignals {
    pub messages_per_minute: f32,

    pub late_night: bool,

    pub rapid_attachment: bool,

    pub total_from_sender: usize,
}

impl Default for TimingAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl TimingAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        current_timestamp_ms: u64,
        is_child_account: bool,
    ) -> Vec<DetectionSignal> {
        self.analyze_with_tz(
            timeline,
            sender_id,
            current_timestamp_ms,
            is_child_account,
            0,
        )
    }

    pub fn analyze_with_tz(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        current_timestamp_ms: u64,
        is_child_account: bool,
        timezone_offset_minutes: i32,
    ) -> Vec<DetectionSignal> {
        let mut signals = Vec::new();

        if let Some(signal) = self.check_message_bombing(timeline, sender_id, current_timestamp_ms)
        {
            signals.push(signal);
        }

        if let Some(signal) = self.check_late_night(
            timeline,
            sender_id,
            current_timestamp_ms,
            is_child_account,
            timezone_offset_minutes,
        ) {
            signals.push(signal);
        }

        if let Some(signal) = self.check_rapid_attachment(timeline, sender_id, current_timestamp_ms)
        {
            signals.push(signal);
        }

        if let Some(signal) =
            self.check_response_asymmetry(timeline, sender_id, current_timestamp_ms)
        {
            signals.push(signal);
        }

        if let Some(signal) =
            self.check_conversation_frequency(timeline, sender_id, current_timestamp_ms)
        {
            signals.push(signal);
        }

        signals
    }

    fn check_message_bombing(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        now_ms: u64,
    ) -> Option<DetectionSignal> {
        let window_5min = 5 * 60 * 1000;
        let recent_count = timeline.count_matching(now_ms.saturating_sub(window_5min), |e| {
            e.sender_id == sender_id
        });

        if recent_count >= 20 {
            let msgs_per_min = recent_count as f32 / 5.0;
            Some(DetectionSignal::context(
                ThreatType::Bullying,
                (0.5 + (msgs_per_min - 4.0) * 0.05).min(0.9),
                Confidence::High,
                SignalFamily::Abuse,
                "abuse.timing.message_bombing",
                format!(
                    "Message bombing detected: {recent_count} messages in 5 minutes ({msgs_per_min:.1}/min)"
                ),
            ))
        } else if recent_count >= 10 {
            Some(DetectionSignal::context(
                ThreatType::Bullying,
                0.4,
                Confidence::Medium,
                SignalFamily::Abuse,
                "abuse.timing.high_message_frequency",
                format!("High message frequency: {recent_count} messages in 5 minutes"),
            ))
        } else {
            None
        }
    }

    fn check_late_night(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        now_ms: u64,
        is_child_account: bool,
        timezone_offset_minutes: i32,
    ) -> Option<DetectionSignal> {
        if !is_child_account {
            return None;
        }

        let last_hour = 60 * 60 * 1000;
        let recent = timeline.events_from_sender(sender_id, now_ms.saturating_sub(last_hour));

        if recent.is_empty() {
            return None;
        }

        let offset_ms = timezone_offset_minutes as i64 * 60 * 1000;
        let local_ms = (now_ms as i64).saturating_add(offset_ms) as u64;
        let hour = ((local_ms / (60 * 60 * 1000)) % 24) as u8;

        let is_late = hour >= 23 || hour <= 5;

        if is_late && recent.len() >= 3 {
            Some(DetectionSignal::context(
                ThreatType::Grooming,
                0.5,
                Confidence::Medium,
                SignalFamily::Conversation,
                "conversation.timing.late_night_minor_contact",
                format!(
                    "Late-night messaging to minor detected: {} messages around {}:00",
                    recent.len(),
                    hour
                ),
            ))
        } else {
            None
        }
    }

    fn check_response_asymmetry(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        _now_ms: u64,
    ) -> Option<DetectionSignal> {
        let all_events = timeline.events_since(0);
        if all_events.len() < 6 {
            return None;
        }

        let mut sender_response_times = Vec::new();
        let mut other_response_times = Vec::new();

        for window in all_events.windows(2) {
            let prev = &window[0];
            let curr = &window[1];
            let gap = curr.timestamp_ms.saturating_sub(prev.timestamp_ms);

            if curr.sender_id == sender_id && prev.sender_id != sender_id {
                sender_response_times.push(gap);
            } else if curr.sender_id != sender_id && prev.sender_id == sender_id {
                other_response_times.push(gap);
            }
        }

        if sender_response_times.len() < 3 || other_response_times.len() < 3 {
            return None;
        }

        let sender_avg_ms =
            sender_response_times.iter().sum::<u64>() / sender_response_times.len() as u64;
        let other_avg_ms =
            other_response_times.iter().sum::<u64>() / other_response_times.len() as u64;

        let thirty_seconds = 30 * 1000;
        let five_minutes = 5 * 60 * 1000;

        if sender_avg_ms < thirty_seconds && other_avg_ms > five_minutes {
            Some(DetectionSignal::context(
                ThreatType::Grooming,
                0.35,
                Confidence::Low,
                SignalFamily::Conversation,
                "conversation.timing.response_asymmetry",
                format!(
                    "Response asymmetry: sender responds in avg {:.0}s, child responds in avg {:.0}s. \
                     Child may feel pressured to respond.",
                    sender_avg_ms as f64 / 1000.0,
                    other_avg_ms as f64 / 1000.0
                ),
            ))
        } else {
            None
        }
    }

    fn check_conversation_frequency(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        now_ms: u64,
    ) -> Option<DetectionSignal> {
        let day_ms: u64 = 24 * 60 * 60 * 1000;
        let day_start = now_ms.saturating_sub(day_ms);

        let msgs_today = timeline.count_matching(day_start, |e| e.sender_id == sender_id);

        if msgs_today >= 50 {
            Some(DetectionSignal::context(
                ThreatType::Grooming,
                0.4,
                Confidence::Medium,
                SignalFamily::Conversation,
                "conversation.timing.excessive_frequency",
                format!(
                    "Excessive conversation frequency: {} messages from same sender in 24 hours. \
                     May indicate obsessive contact or grooming behavior.",
                    msgs_today
                ),
            ))
        } else {
            None
        }
    }

    fn check_rapid_attachment(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        now_ms: u64,
    ) -> Option<DetectionSignal> {
        let all_from_sender = timeline.events_from_sender(sender_id, 0);

        if all_from_sender.len() < 2 {
            return None;
        }

        let first_msg = all_from_sender[0].timestamp_ms;
        let elapsed_hours = (now_ms - first_msg) as f32 / (1000.0 * 3600.0);

        if elapsed_hours <= 2.0 && all_from_sender.len() >= 15 {
            Some(DetectionSignal::context(
                ThreatType::Grooming,
                0.45,
                Confidence::Medium,
                SignalFamily::Conversation,
                "conversation.timing.rapid_attachment",
                format!(
                    "Rapid attachment: {} messages within {:.1} hours of first contact",
                    all_from_sender.len(),
                    elapsed_hours
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

    fn make_timeline_msgs(
        sender: &str,
        count: usize,
        start_ms: u64,
        interval_ms: u64,
    ) -> ConversationTimeline {
        let mut timeline = ConversationTimeline::new("conv_1".to_string(), 500);
        for i in 0..count {
            timeline.push(ContextEvent {
                event_id: 0,
                timestamp_ms: start_ms + i as u64 * interval_ms,
                sender_id: sender.to_string(),
                conversation_id: "conv_1".to_string(),
                kind: EventKind::NormalConversation,
                confidence: 1.0,
            });
        }
        timeline
    }

    #[test]
    fn no_signals_for_normal_conversation() {
        let analyzer = TimingAnalyzer::new();

        let base = 10 * 3600 * 1000;
        let timeline = make_timeline_msgs("alice", 5, base, 60000);

        let signals = analyzer.analyze(&timeline, "alice", base + 5 * 60000, true);
        assert!(signals.is_empty(), "Expected no signals, got: {signals:?}");
    }

    #[test]
    fn detects_message_bombing() {
        let analyzer = TimingAnalyzer::new();

        let now = 5 * 60 * 1000;
        let timeline = make_timeline_msgs("harasser", 25, 0, 12000);

        let signals = analyzer.analyze(&timeline, "harasser", now, false);
        let bombing = signals.iter().find(|s| s.explanation.contains("bombing"));
        assert!(
            bombing.is_some(),
            "Expected message bombing, got: {signals:?}"
        );
    }

    #[test]
    fn detects_high_frequency() {
        let analyzer = TimingAnalyzer::new();
        let now = 5 * 60 * 1000;
        let timeline = make_timeline_msgs("sender", 12, 0, 25000);

        let signals = analyzer.analyze(&timeline, "sender", now, false);
        assert!(
            signals
                .iter()
                .any(|s| s.explanation.contains("frequency") || s.explanation.contains("bombing")),
            "Expected high frequency signal, got: {signals:?}"
        );
    }

    #[test]
    fn detects_late_night_messaging_to_child() {
        let analyzer = TimingAnalyzer::new();

        let base_time = 2 * 3600 * 1000;
        let timeline = make_timeline_msgs("adult", 5, base_time, 60000);

        let signals = analyzer.analyze(&timeline, "adult", base_time + 5 * 60000, true);
        let late = signals
            .iter()
            .find(|s| s.explanation.contains("Late-night"));
        assert!(
            late.is_some(),
            "Expected late-night detection, got: {signals:?}"
        );
    }

    #[test]
    fn no_late_night_for_adult_account() {
        let analyzer = TimingAnalyzer::new();
        let base_time = 2 * 3600 * 1000;

        let timeline = make_timeline_msgs("someone", 5, base_time, 60000);

        let signals = analyzer.analyze(&timeline, "someone", base_time + 5 * 60000, false);
        assert!(!signals.iter().any(|s| s.explanation.contains("Late-night")));
    }

    #[test]
    fn detects_rapid_attachment() {
        let analyzer = TimingAnalyzer::new();

        let timeline = make_timeline_msgs("stranger", 20, 0, 3 * 60 * 1000);

        let signals = analyzer.analyze(&timeline, "stranger", 60 * 60 * 1000, true);
        let rapid = signals
            .iter()
            .find(|s| s.explanation.contains("Rapid attachment"));
        assert!(
            rapid.is_some(),
            "Expected rapid attachment, got: {signals:?}"
        );
    }

    #[test]
    fn detects_response_asymmetry() {
        let analyzer = TimingAnalyzer::new();
        let mut timeline = ConversationTimeline::new("conv_1".to_string(), 500);

        let min = 60 * 1000u64;
        let events = vec![
            ("child", 0u64),
            ("predator", 10 * 1000),
            ("child", 10 * 1000 + 6 * min),
            ("predator", 10 * 1000 + 6 * min + 15 * 1000),
            ("child", 10 * 1000 + 6 * min + 15 * 1000 + 7 * min),
            (
                "predator",
                10 * 1000 + 6 * min + 15 * 1000 + 7 * min + 20 * 1000,
            ),
            (
                "child",
                10 * 1000 + 6 * min + 15 * 1000 + 7 * min + 20 * 1000 + 8 * min,
            ),
            (
                "predator",
                10 * 1000 + 6 * min + 15 * 1000 + 7 * min + 20 * 1000 + 8 * min + 5 * 1000,
            ),
        ];
        for (sender, ts) in events {
            timeline.push(ContextEvent {
                event_id: 0,
                timestamp_ms: ts,
                sender_id: sender.to_string(),
                conversation_id: "conv_1".to_string(),
                kind: EventKind::NormalConversation,
                confidence: 1.0,
            });
        }

        let now = 10 * 1000 + 6 * min + 15 * 1000 + 7 * min + 20 * 1000 + 8 * min + 5 * 1000;
        let signals = analyzer.analyze(&timeline, "predator", now, true);
        let asymmetry = signals.iter().find(|s| s.explanation.contains("asymmetry"));
        assert!(
            asymmetry.is_some(),
            "Expected response asymmetry, got: {signals:?}"
        );
        assert!((asymmetry.unwrap().score - 0.35).abs() < 0.01);
    }

    #[test]
    fn no_asymmetry_equal_response() {
        let analyzer = TimingAnalyzer::new();
        let mut timeline = ConversationTimeline::new("conv_1".to_string(), 500);

        let min = 60 * 1000u64;
        let events = vec![
            ("alice", 0u64),
            ("bob", min),
            ("alice", 2 * min),
            ("bob", 3 * min),
            ("alice", 4 * min),
            ("bob", 5 * min),
            ("alice", 6 * min),
            ("bob", 7 * min),
        ];
        for (sender, ts) in events {
            timeline.push(ContextEvent {
                event_id: 0,
                timestamp_ms: ts,
                sender_id: sender.to_string(),
                conversation_id: "conv_1".to_string(),
                kind: EventKind::NormalConversation,
                confidence: 1.0,
            });
        }

        let signals = analyzer.analyze(&timeline, "bob", 7 * min, true);
        let asymmetry = signals.iter().find(|s| s.explanation.contains("asymmetry"));
        assert!(
            asymmetry.is_none(),
            "Equal response times should not trigger asymmetry"
        );
    }

    #[test]
    fn detects_excessive_frequency() {
        let analyzer = TimingAnalyzer::new();

        let base = 10 * 3600 * 1000u64;

        let timeline = make_timeline_msgs("stalker", 55, base, 60 * 1000);

        let now = base + 55 * 60 * 1000;
        let signals = analyzer.analyze(&timeline, "stalker", now, true);
        let freq = signals
            .iter()
            .find(|s| s.explanation.contains("Excessive conversation frequency"));
        assert!(
            freq.is_some(),
            "Expected frequency signal, got: {signals:?}"
        );
        assert!((freq.unwrap().score - 0.4).abs() < 0.01);
    }

    #[test]
    fn no_frequency_alert_under_50() {
        let analyzer = TimingAnalyzer::new();
        let base = 10 * 3600 * 1000u64;
        let timeline = make_timeline_msgs("friend", 30, base, 60 * 1000);

        let now = base + 30 * 60 * 1000;
        let signals = analyzer.analyze(&timeline, "friend", now, true);
        let freq = signals
            .iter()
            .find(|s| s.explanation.contains("Excessive conversation frequency"));
        assert!(freq.is_none(), "30 msgs should not trigger frequency alert");
    }

    #[test]
    fn late_night_uses_local_time_not_utc() {
        let analyzer = TimingAnalyzer::new();

        // 21:00 UTC = 00:00 UTC+3 (Ukraine midnight)
        let base_time = 21 * 3600 * 1000u64;
        let timeline = make_timeline_msgs("adult", 5, base_time, 60000);
        let now = base_time + 5 * 60000;

        // Without timezone offset (UTC): 21:00 is NOT late night (23-05)
        let signals_utc = analyzer.analyze_with_tz(&timeline, "adult", now, true, 0);
        assert!(
            !signals_utc
                .iter()
                .any(|s| s.explanation.contains("Late-night")),
            "21:00 UTC should NOT be flagged as late night"
        );

        // With UTC+3 offset: 21:00 UTC → 00:00 local = late night!
        let signals_local = analyzer.analyze_with_tz(&timeline, "adult", now, true, 180);
        assert!(
            signals_local
                .iter()
                .any(|s| s.explanation.contains("Late-night")),
            "21:00 UTC with UTC+3 offset = midnight, should be flagged as late night"
        );
    }

    #[test]
    fn late_night_negative_timezone_offset() {
        let analyzer = TimingAnalyzer::new();

        // 03:00 UTC = 22:00 UTC-5 (New York, not late by the 23-05 window)
        let base_time = 3 * 3600 * 1000u64;
        let timeline = make_timeline_msgs("adult", 5, base_time, 60000);
        let now = base_time + 5 * 60000;

        // At UTC: 03:00 IS late night
        let signals_utc = analyzer.analyze_with_tz(&timeline, "adult", now, true, 0);
        assert!(
            signals_utc
                .iter()
                .any(|s| s.explanation.contains("Late-night")),
            "03:00 UTC should be flagged as late night"
        );

        // With UTC-5: 03:00 UTC = 22:00 local → NOT late night
        let signals_local = analyzer.analyze_with_tz(&timeline, "adult", now, true, -300);
        assert!(
            !signals_local
                .iter()
                .any(|s| s.explanation.contains("Late-night")),
            "03:00 UTC with UTC-5 = 22:00 local, should NOT be flagged"
        );
    }
}
