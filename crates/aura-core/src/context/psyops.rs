use crate::types::{Confidence, DetectionSignal, SignalFamily, ThreatType};

use super::contact::ContactProfiler;
use super::events::EventKind;
use super::tracker::ConversationTimeline;

/// Detects enemy psychological operations and social engineering targeting military personnel.
///
/// Tracks sustained psyops patterns such as demoralization messaging, trust-undermining
/// in command structures, and intelligence gathering from suspicious contacts.
pub struct PsyopsDetector {
    /// Lookback window in milliseconds (default 7 days).
    window_ms: u64,
}

impl Default for PsyopsDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PsyopsDetector {
    /// Creates a new psyops detector with default settings.
    pub fn new() -> Self {
        Self {
            window_ms: 7 * 24 * 60 * 60 * 1000,
        }
    }

    /// Analyzes a conversation timeline for psyops patterns from a specific sender.
    pub fn analyze(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        now_ms: u64,
        contact_profiler: &ContactProfiler,
    ) -> Vec<DetectionSignal> {
        let mut signals = Vec::with_capacity(4);
        let window_start = now_ms.saturating_sub(self.window_ms);

        let mut psyops_count = 0usize;
        let mut intel_count = 0usize;
        let mut phishing_count = 0usize;
        let mut disinfo_count = 0usize;
        let mut phishing_subtypes: Vec<String> = Vec::new();
        let mut has_volga = false;
        let mut has_military_context = false;

        for event in timeline.events_since(window_start) {
            if event.kind.is_opsec_indicator() || event.kind.is_psyops_indicator() {
                has_military_context = true;
            }
            if &*event.sender_id != sender_id {
                continue;
            }
            match event.kind {
                EventKind::PsyopsPattern => {
                    psyops_count += 1;
                    if let Some(ref st) = event.subtype {
                        if st == "surrender_volga" {
                            has_volga = true;
                        }
                    }
                }
                EventKind::IntelGathering => intel_count += 1,
                EventKind::MilitaryPhishing => {
                    phishing_count += 1;
                    if let Some(ref st) = event.subtype {
                        phishing_subtypes.push(st.clone());
                    }
                }
                EventKind::MilitaryDisinfo => disinfo_count += 1,
                _ => {}
            }
        }

        let is_new = contact_profiler.is_new_contact(sender_id);
        let total_events = psyops_count + intel_count + phishing_count + disinfo_count;

        // Military phishing — single event is actionable
        if phishing_count >= 1 {
            let score = if is_new { 0.9 } else { 0.75 };
            let reason_code = if phishing_subtypes.iter().any(|s| s == "phishing_diia") {
                "conversation.psyops.phishing_diia"
            } else if phishing_subtypes.iter().any(|s| s == "phishing_tck") {
                "conversation.psyops.phishing_tck"
            } else {
                "conversation.psyops.military_phishing"
            };
            signals.push(DetectionSignal::context(
                ThreatType::MilitarySocialEng,
                score,
                Confidence::High,
                SignalFamily::Link,
                reason_code,
                format!(
                    "Detected {} military-specific phishing attempt(s)",
                    phishing_count
                ),
            ));
        }

        // Sustained psyops pattern (demoralization, trust-undermining)
        if psyops_count >= 2 {
            let base_score: f32 = if has_volga {
                if has_military_context && total_events > 1 {
                    0.85
                } else {
                    0.3
                }
            } else if psyops_count >= 4 {
                0.85
            } else if psyops_count >= 3 {
                0.75
            } else {
                0.6
            };
            let score = if is_new {
                (base_score + 0.1).min(0.95f32)
            } else {
                base_score
            };
            signals.push(DetectionSignal::context(
                ThreatType::Psyops,
                score,
                if psyops_count >= 3 {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
                SignalFamily::Content,
                "conversation.psyops.demoralization_pattern",
                format!(
                    "Sender exhibits {} psyops/demoralization pattern(s)",
                    psyops_count
                ),
            ));
        }

        // Intelligence gathering escalation: casual → probing → direct requests
        if intel_count >= 2 {
            let base_score: f32 = if intel_count >= 4 {
                0.9
            } else if intel_count >= 3 {
                0.8
            } else {
                0.65
            };
            let score = if is_new {
                (base_score + 0.1).min(0.95f32)
            } else {
                base_score
            };
            signals.push(DetectionSignal::context(
                ThreatType::MilitarySocialEng,
                score,
                Confidence::High,
                SignalFamily::Conversation,
                "conversation.psyops.intel_escalation",
                format!(
                    "Sender made {} intelligence gathering attempt(s)",
                    intel_count
                ),
            ));
        }

        // Multi-vector: psyops + intel gathering = coordinated operation
        if psyops_count >= 1 && intel_count >= 1 {
            let score = (0.7 + total_events as f32 * 0.04).min(0.95f32);
            signals.push(DetectionSignal::context(
                ThreatType::Psyops,
                score,
                Confidence::High,
                SignalFamily::Conversation,
                "conversation.psyops.multi_vector",
                format!(
                    "Sender combines psyops ({}) with intel gathering ({}) — possible coordinated operation",
                    psyops_count, intel_count
                ),
            ));
        }

        signals
    }
}

#[cfg(test)]
mod tests {
    use super::super::events::ContextEvent;
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
        }
    }

    fn make_event_with_subtype(
        sender: &str,
        conv: &str,
        kind: EventKind,
        ts: u64,
        subtype: &str,
    ) -> ContextEvent {
        ContextEvent {
            event_id: 0,
            timestamp_ms: ts,
            sender_id: sender.into(),
            conversation_id: conv.into(),
            kind,
            confidence: 0.8,
            subtype: Some(subtype.to_string()),
        }
    }

    fn setup_profiler(events: &[ContextEvent]) -> ContactProfiler {
        let mut profiler = ContactProfiler::new();
        for event in events {
            profiler.record_event(event);
        }
        profiler
    }

    #[test]
    fn no_psyops_in_normal_conversation() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![
            make_event("contact", "conv_1", EventKind::NormalConversation, 1000),
        ];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = PsyopsDetector::new();
        let signals = detector.analyze(&timeline, "contact", 5000, &profiler);
        assert!(signals.is_empty());
    }

    #[test]
    fn military_phishing_single_event_triggers() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![make_event(
            "attacker",
            "conv_1",
            EventKind::MilitaryPhishing,
            1000,
        )];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = PsyopsDetector::new();
        let signals = detector.analyze(&timeline, "attacker", 5000, &profiler);
        assert!(!signals.is_empty(), "Military phishing should trigger");
        assert_eq!(signals[0].threat_type, ThreatType::MilitarySocialEng);
    }

    #[test]
    fn sustained_psyops_pattern() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![
            make_event("psyop", "conv_1", EventKind::PsyopsPattern, 1000),
            make_event("psyop", "conv_1", EventKind::PsyopsPattern, 2000),
            make_event("psyop", "conv_1", EventKind::PsyopsPattern, 3000),
        ];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = PsyopsDetector::new();
        let signals = detector.analyze(&timeline, "psyop", 5000, &profiler);
        let demoralization = signals.iter().find(|s| {
            s.reason_code.contains("demoralization")
        });
        assert!(
            demoralization.is_some(),
            "Should detect demoralization pattern"
        );
        assert!(demoralization.unwrap().score >= 0.7);
    }

    #[test]
    fn intel_gathering_escalation() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![
            make_event("spy", "conv_1", EventKind::IntelGathering, 1000),
            make_event("spy", "conv_1", EventKind::IntelGathering, 2000),
            make_event("spy", "conv_1", EventKind::IntelGathering, 3000),
        ];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = PsyopsDetector::new();
        let signals = detector.analyze(&timeline, "spy", 5000, &profiler);
        let intel = signals
            .iter()
            .find(|s| s.reason_code.contains("intel_escalation"));
        assert!(intel.is_some(), "Should detect intel escalation");
        assert!(intel.unwrap().score >= 0.7);
    }

    #[test]
    fn multi_vector_coordinated_operation() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![
            make_event("agent", "conv_1", EventKind::PsyopsPattern, 1000),
            make_event("agent", "conv_1", EventKind::PsyopsPattern, 2000),
            make_event("agent", "conv_1", EventKind::IntelGathering, 3000),
            make_event("agent", "conv_1", EventKind::IntelGathering, 4000),
        ];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = PsyopsDetector::new();
        let signals = detector.analyze(&timeline, "agent", 5000, &profiler);
        let multi = signals
            .iter()
            .find(|s| s.reason_code.contains("multi_vector"));
        assert!(
            multi.is_some(),
            "Should detect multi-vector coordinated operation"
        );
        assert!(multi.unwrap().score >= 0.7);
    }

    #[test]
    fn new_contact_gets_higher_score() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![make_event(
            "new_spy",
            "conv_1",
            EventKind::MilitaryPhishing,
            1000,
        )];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = PsyopsDetector::new();
        let signals = detector.analyze(&timeline, "new_spy", 5000, &profiler);
        assert!(!signals.is_empty());
        // New contacts should get boosted scores
        assert!(
            signals[0].score >= 0.85,
            "New contact phishing should have high score"
        );
    }

    #[test]
    fn other_sender_events_ignored() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![
            make_event("alice", "conv_1", EventKind::PsyopsPattern, 1000),
            make_event("alice", "conv_1", EventKind::PsyopsPattern, 2000),
            make_event("alice", "conv_1", EventKind::PsyopsPattern, 3000),
        ];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = PsyopsDetector::new();
        let signals = detector.analyze(&timeline, "bob", 5000, &profiler);
        assert!(signals.is_empty(), "Should not count other sender's events");
    }

    #[test]
    fn test_phishing_diia_subtype() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![make_event_with_subtype(
            "attacker",
            "conv_1",
            EventKind::MilitaryPhishing,
            1000,
            "phishing_diia",
        )];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = PsyopsDetector::new();
        let signals = detector.analyze(&timeline, "attacker", 5000, &profiler);
        assert!(!signals.is_empty(), "Should detect phishing");
        let phishing = signals
            .iter()
            .find(|s| s.reason_code.contains("phishing_diia"));
        assert!(
            phishing.is_some(),
            "Should use phishing_diia reason code, got: {:?}",
            signals.iter().map(|s| &s.reason_code).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_volga_with_military_context() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![
            make_event_with_subtype(
                "psyop",
                "conv_1",
                EventKind::PsyopsPattern,
                1000,
                "surrender_volga",
            ),
            make_event("psyop", "conv_1", EventKind::PsyopsPattern, 2000),
            make_event("psyop", "conv_1", EventKind::IntelGathering, 3000),
        ];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = PsyopsDetector::new();
        let signals = detector.analyze(&timeline, "psyop", 5000, &profiler);
        let demoralization = signals
            .iter()
            .find(|s| s.reason_code.contains("demoralization"));
        assert!(
            demoralization.is_some(),
            "Should detect demoralization pattern"
        );
        assert!(
            demoralization.unwrap().score >= 0.8,
            "Volga with military context should score >= 0.8, got {}",
            demoralization.unwrap().score
        );
    }

    #[test]
    fn test_volga_without_military_context() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![make_event_with_subtype(
            "psyop",
            "conv_1",
            EventKind::PsyopsPattern,
            1000,
            "surrender_volga",
        )];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = PsyopsDetector::new();
        let signals = detector.analyze(&timeline, "psyop", 5000, &profiler);
        let demoralization = signals
            .iter()
            .find(|s| s.reason_code.contains("demoralization"));
        assert!(
            demoralization.is_none(),
            "Single surrender_volga event should not trigger sustained pattern (needs >= 2)"
        );
    }
}
