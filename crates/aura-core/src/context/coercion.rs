use crate::types::{Confidence, DetectionLayer, DetectionSignal, ThreatType};

use super::events::EventKind;
use super::tracker::ConversationTimeline;

pub struct CoercionDetector;

impl Default for CoercionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CoercionDetector {
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

        if let Some(signal) = self.check_suicide_coercion(timeline, sender_id, window_start) {
            signals.push(signal);
        }

        if let Some(signal) = self.check_reputation_blackmail(timeline, sender_id, window_start) {
            signals.push(signal);
        }

        if let Some(signal) = self.check_debt_leverage(timeline, sender_id, window_start) {
            signals.push(signal);
        }

        if let Some(signal) = self.check_combined_coercion(timeline, sender_id, window_start) {
            signals.push(signal);
        }

        signals
    }

    fn check_suicide_coercion(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        window_start: u64,
    ) -> Option<DetectionSignal> {
        let count =
            timeline.count_events(sender_id, &EventKind::SuicideCoercion, window_start);

        if count >= 1 {
            let score = if count >= 2 {
                (0.85 + (count as f32 - 2.0) * 0.05).min(0.95)
            } else {
                0.75
            };
            Some(DetectionSignal {
                threat_type: ThreatType::Manipulation,
                score,
                confidence: Confidence::High,
                layer: DetectionLayer::ContextAnalysis,
                explanation: format!(
                    "Suicide coercion detected: sender using self-harm threats to control victim ({} instance{}). \
                     This is psychological abuse, NOT a genuine cry for help.",
                    count,
                    if count > 1 { "s" } else { "" }
                ),
            })
        } else {
            None
        }
    }

    fn check_reputation_blackmail(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        window_start: u64,
    ) -> Option<DetectionSignal> {
        let count =
            timeline.count_events(sender_id, &EventKind::ReputationThreat, window_start);

        if count >= 2 {
            let score = (0.6 + (count as f32 - 2.0) * 0.1).min(0.85);
            Some(DetectionSignal {
                threat_type: ThreatType::Manipulation,
                score,
                confidence: if count >= 4 {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
                layer: DetectionLayer::ContextAnalysis,
                explanation: format!(
                    "Reputation blackmail pattern: {} threats to damage victim's social standing",
                    count
                ),
            })
        } else {
            None
        }
    }

    fn check_debt_leverage(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        window_start: u64,
    ) -> Option<DetectionSignal> {
        let count =
            timeline.count_events(sender_id, &EventKind::DebtCreation, window_start);

        if count >= 2 {
            let score = (0.5 + (count as f32 - 2.0) * 0.1).min(0.8);
            Some(DetectionSignal {
                threat_type: ThreatType::Manipulation,
                score,
                confidence: if count >= 4 {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
                layer: DetectionLayer::ContextAnalysis,
                explanation: format!(
                    "Debt leverage pattern: {} instances of obligation/guilt used to coerce victim",
                    count
                ),
            })
        } else {
            None
        }
    }

    fn check_combined_coercion(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        window_start: u64,
    ) -> Option<DetectionSignal> {
        let events = timeline.events_from_sender(sender_id, window_start);

        let mut coercion_types = std::collections::HashSet::new();
        let mut total = 0usize;

        for event in &events {
            match event.kind {
                EventKind::SuicideCoercion => {
                    coercion_types.insert("suicide");
                    total += 1;
                }
                EventKind::ReputationThreat => {
                    coercion_types.insert("reputation");
                    total += 1;
                }
                EventKind::DebtCreation => {
                    coercion_types.insert("debt");
                    total += 1;
                }
                EventKind::ScreenshotThreat => {
                    coercion_types.insert("screenshot");
                    total += 1;
                }
                _ => {}
            }
        }

        if coercion_types.len() >= 2 && total >= 3 {
            let score = (0.75 + (coercion_types.len() as f32 - 2.0) * 0.1
                + (total as f32 - 3.0) * 0.02)
                .min(0.95);
            Some(DetectionSignal {
                threat_type: ThreatType::Manipulation,
                score,
                confidence: Confidence::High,
                layer: DetectionLayer::ContextAnalysis,
                explanation: format!(
                    "Multi-vector coercive control: {} coercion types across {} events ({}). \
                     Sender is using multiple pressure tactics to control victim.",
                    coercion_types.len(),
                    total,
                    coercion_types.into_iter().collect::<Vec<_>>().join(", ")
                ),
            })
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
    fn single_suicide_coercion_high_score() {
        let detector = CoercionDetector::new();
        let timeline = make_timeline(vec![
            ("abuser", EventKind::SuicideCoercion, 1000),
        ]);
        let signals = detector.analyze(&timeline, "abuser", 0);
        let suicide = signals
            .iter()
            .find(|s| s.explanation.contains("Suicide coercion"));
        assert!(
            suicide.is_some(),
            "Single suicide coercion should be detected immediately"
        );
        assert!(
            suicide.unwrap().score >= 0.75,
            "Single suicide coercion should score >= 0.75, got {}",
            suicide.unwrap().score
        );
    }

    #[test]
    fn suicide_coercion_is_manipulation_not_selfharm() {
        let detector = CoercionDetector::new();
        let timeline = make_timeline(vec![
            ("abuser", EventKind::SuicideCoercion, 1000),
        ]);
        let signals = detector.analyze(&timeline, "abuser", 0);
        assert!(
            signals
                .iter()
                .all(|s| s.threat_type == ThreatType::Manipulation),
            "Suicide coercion must be Manipulation, NOT SelfHarm"
        );
    }

    #[test]
    fn repeated_reputation_threat_escalates() {
        let detector = CoercionDetector::new();
        let timeline = make_timeline(vec![
            ("bully", EventKind::ReputationThreat, 1000),
            ("bully", EventKind::ReputationThreat, 2000),
        ]);
        let signals = detector.analyze(&timeline, "bully", 0);
        let rep = signals
            .iter()
            .find(|s| s.explanation.contains("Reputation blackmail"));
        assert!(rep.is_some(), "2+ reputation threats should trigger detection");
        assert!(rep.unwrap().score >= 0.6);
    }

    #[test]
    fn debt_creation_needs_repetition() {
        let detector = CoercionDetector::new();

        let single = make_timeline(vec![("abuser", EventKind::DebtCreation, 1000)]);
        let signals = detector.analyze(&single, "abuser", 0);
        let debt = signals
            .iter()
            .find(|s| s.explanation.contains("Debt leverage"));
        assert!(debt.is_none(), "Single debt event should not trigger pattern");

        let repeated = make_timeline(vec![
            ("abuser", EventKind::DebtCreation, 1000),
            ("abuser", EventKind::DebtCreation, 2000),
        ]);
        let signals = detector.analyze(&repeated, "abuser", 0);
        let debt = signals
            .iter()
            .find(|s| s.explanation.contains("Debt leverage"));
        assert!(debt.is_some(), "2+ debt events should trigger pattern");
    }

    #[test]
    fn combined_coercion_patterns() {
        let detector = CoercionDetector::new();
        let timeline = make_timeline(vec![
            ("abuser", EventKind::DebtCreation, 1000),
            ("abuser", EventKind::ReputationThreat, 2000),
            ("abuser", EventKind::DebtCreation, 3000),
        ]);
        let signals = detector.analyze(&timeline, "abuser", 0);
        let combined = signals
            .iter()
            .find(|s| s.explanation.contains("Multi-vector"));
        assert!(
            combined.is_some(),
            "2+ coercion types with 3+ events should trigger combined detection"
        );
        assert!(combined.unwrap().score >= 0.75);
    }
}
