use crate::types::{
    Action, ActionRecommendation, AlertPriority, FollowUpAction, ProtectionLevel, ThreatType,
};

pub fn decide_action(score: f32, protection_level: ProtectionLevel) -> Action {
    let thresholds = ActionThresholds::for_level(protection_level);

    if score >= thresholds.block {
        Action::Block
    } else if score >= thresholds.warn {
        Action::Warn
    } else if score >= thresholds.blur {
        Action::Blur
    } else if score >= thresholds.mark {
        Action::Mark
    } else {
        Action::Allow
    }
}

pub fn decide_action_v2(
    threat_type: ThreatType,
    score: f32,
    protection_level: ProtectionLevel,
) -> (Action, ActionRecommendation) {
    match threat_type {
        ThreatType::SelfHarm => {
            let parent_alert = if score >= 0.6 {
                AlertPriority::Urgent
            } else if score >= 0.4 {
                AlertPriority::High
            } else {
                AlertPriority::Medium
            };
            (
                Action::Warn,
                ActionRecommendation {
                    parent_alert,
                    follow_ups: vec![FollowUpAction::MonitorConversation],
                    crisis_resources: true,
                },
            )
        }
        ThreatType::Grooming => {
            let action = if score >= 0.85 {
                Action::Block
            } else if score >= 0.6 {
                Action::Warn
            } else {
                decide_action(score, protection_level)
            };
            let parent_alert = if score >= 0.5 {
                AlertPriority::High
            } else {
                AlertPriority::Low
            };
            let mut follow_ups = vec![FollowUpAction::ReviewContactProfile];
            if score >= 0.6 {
                follow_ups.push(FollowUpAction::BlockSuggested);
            }
            (
                action,
                ActionRecommendation {
                    parent_alert,
                    follow_ups,
                    crisis_resources: false,
                },
            )
        }
        ThreatType::Bullying => {
            let action = if score >= 0.9 {
                Action::Block
            } else if score >= 0.7 {
                Action::Warn
            } else {
                decide_action(score, protection_level)
            };
            let parent_alert = if score >= 0.7 {
                AlertPriority::High
            } else if score >= 0.5 {
                AlertPriority::Medium
            } else {
                AlertPriority::Low
            };
            (
                action,
                ActionRecommendation {
                    parent_alert,
                    follow_ups: vec![FollowUpAction::MonitorConversation],
                    crisis_resources: false,
                },
            )
        }
        ThreatType::Manipulation => {
            let action = if score >= 0.9 {
                Action::Block
            } else if score >= 0.65 {
                Action::Warn
            } else {
                decide_action(score, protection_level)
            };
            let parent_alert = if score >= 0.6 {
                AlertPriority::Medium
            } else {
                AlertPriority::Low
            };
            (
                action,
                ActionRecommendation {
                    parent_alert,
                    follow_ups: vec![FollowUpAction::ReviewContactProfile],
                    crisis_resources: false,
                },
            )
        }
        ThreatType::Explicit => {
            let action = if score >= 0.8 {
                Action::Block
            } else if score >= 0.7 {
                Action::Warn
            } else {
                decide_action(score, protection_level)
            };

            (
                action,
                ActionRecommendation {
                    parent_alert: AlertPriority::High,
                    follow_ups: vec![FollowUpAction::ReportToAuthorities],
                    crisis_resources: false,
                },
            )
        }
        ThreatType::Doxxing => {
            let action = if score >= 0.75 {
                Action::Block
            } else if score >= 0.5 {
                Action::Warn
            } else {
                decide_action(score, protection_level)
            };

            (
                action,
                ActionRecommendation {
                    parent_alert: AlertPriority::High,
                    follow_ups: vec![FollowUpAction::ReportToAuthorities],
                    crisis_resources: false,
                },
            )
        }
        ThreatType::Threat => {
            let action = if score >= 0.9 {
                Action::Block
            } else if score >= 0.7 {
                Action::Warn
            } else {
                decide_action(score, protection_level)
            };
            let parent_alert = if score >= 0.7 {
                AlertPriority::High
            } else {
                AlertPriority::Medium
            };
            let mut follow_ups = vec![FollowUpAction::MonitorConversation];
            if score >= 0.8 {
                follow_ups.push(FollowUpAction::BlockSuggested);
            }
            (
                action,
                ActionRecommendation {
                    parent_alert,
                    follow_ups,
                    crisis_resources: false,
                },
            )
        }

        ThreatType::PiiLeakage => {
            let action = if score >= 0.7 {
                Action::Warn
            } else if score >= 0.4 {
                Action::Mark
            } else {
                decide_action(score, protection_level)
            };
            let parent_alert = if score >= 0.5 {
                AlertPriority::High
            } else {
                AlertPriority::Medium
            };
            (
                action,
                ActionRecommendation {
                    parent_alert,
                    follow_ups: vec![
                        FollowUpAction::MonitorConversation,
                        FollowUpAction::ReviewContactProfile,
                    ],
                    crisis_resources: false,
                },
            )
        }

        _ => {
            let action = decide_action(score, protection_level);
            let parent_alert = if score >= 0.7 {
                AlertPriority::Medium
            } else {
                AlertPriority::None
            };
            (
                action,
                ActionRecommendation {
                    parent_alert,
                    follow_ups: vec![],
                    crisis_resources: false,
                },
            )
        }
    }
}

struct ActionThresholds {
    mark: f32,
    blur: f32,
    warn: f32,
    block: f32,
}

impl ActionThresholds {
    fn for_level(level: ProtectionLevel) -> Self {
        match level {
            ProtectionLevel::Off => Self {
                mark: 2.0,
                blur: 2.0,
                warn: 2.0,
                block: 2.0,
            },

            ProtectionLevel::Low => Self {
                mark: 0.6,
                blur: 0.75,
                warn: 0.85,
                block: 0.95,
            },

            ProtectionLevel::Medium => Self {
                mark: 0.3,
                blur: 0.5,
                warn: 0.7,
                block: 0.9,
            },

            ProtectionLevel::High => Self {
                mark: 0.2,
                blur: 0.35,
                warn: 0.5,
                block: 0.8,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_message_is_allowed() {
        assert_eq!(decide_action(0.0, ProtectionLevel::High), Action::Allow);
        assert_eq!(decide_action(0.1, ProtectionLevel::Medium), Action::Allow);
    }

    #[test]
    fn obvious_threat_is_blocked() {
        assert_eq!(decide_action(0.95, ProtectionLevel::Medium), Action::Block);
        assert_eq!(decide_action(0.95, ProtectionLevel::Low), Action::Block);
    }

    #[test]
    fn medium_threat_is_blurred() {
        assert_eq!(decide_action(0.55, ProtectionLevel::Medium), Action::Blur);
    }

    #[test]
    fn protection_off_allows_everything() {
        assert_eq!(decide_action(1.0, ProtectionLevel::Off), Action::Allow);
    }

    #[test]
    fn high_protection_is_more_aggressive() {
        assert_eq!(decide_action(0.25, ProtectionLevel::Medium), Action::Allow);
        assert_eq!(decide_action(0.25, ProtectionLevel::High), Action::Mark);
    }

    #[test]
    fn teen_minimum_low_still_catches_clear_threats() {
        assert_eq!(decide_action(0.9, ProtectionLevel::Low), Action::Warn);
        assert_eq!(decide_action(0.96, ProtectionLevel::Low), Action::Block);
    }

    #[test]
    fn selfharm_never_blocked() {
        let (action, rec) = decide_action_v2(ThreatType::SelfHarm, 0.95, ProtectionLevel::High);
        assert_eq!(action, Action::Warn, "Self-harm must NEVER be blocked");
        assert!(rec.crisis_resources, "Self-harm must show crisis resources");
    }

    #[test]
    fn selfharm_crisis_resources_always() {
        let (_, rec_low) = decide_action_v2(ThreatType::SelfHarm, 0.3, ProtectionLevel::Medium);
        let (_, rec_high) = decide_action_v2(ThreatType::SelfHarm, 0.9, ProtectionLevel::Medium);
        assert!(rec_low.crisis_resources, "Crisis resources at low score");
        assert!(rec_high.crisis_resources, "Crisis resources at high score");
    }

    #[test]
    fn selfharm_urgent_parent_alert() {
        let (_, rec) = decide_action_v2(ThreatType::SelfHarm, 0.7, ProtectionLevel::High);
        assert_eq!(rec.parent_alert, AlertPriority::Urgent);
    }

    #[test]
    fn grooming_parent_alert_at_50() {
        let (_, rec) = decide_action_v2(ThreatType::Grooming, 0.55, ProtectionLevel::High);
        assert!(
            rec.parent_alert >= AlertPriority::High,
            "Grooming ≥0.5 should alert parent at High, got {:?}",
            rec.parent_alert
        );
    }

    #[test]
    fn grooming_block_suggested() {
        let (_, rec) = decide_action_v2(ThreatType::Grooming, 0.7, ProtectionLevel::High);
        assert!(
            rec.follow_ups.contains(&FollowUpAction::BlockSuggested),
            "Grooming ≥0.6 should suggest blocking"
        );
    }

    #[test]
    fn explicit_always_alerts_parent() {
        let (_, rec) = decide_action_v2(ThreatType::Explicit, 0.3, ProtectionLevel::Medium);
        assert!(
            rec.parent_alert >= AlertPriority::High,
            "Explicit content should always alert parent"
        );
    }

    #[test]
    fn doxxing_always_report() {
        let (_, rec) = decide_action_v2(ThreatType::Doxxing, 0.5, ProtectionLevel::Medium);
        assert!(
            rec.follow_ups
                .contains(&FollowUpAction::ReportToAuthorities),
            "Doxxing should recommend reporting to authorities"
        );
        assert!(rec.parent_alert >= AlertPriority::High);
    }

    #[test]
    fn bullying_monitor_conversation() {
        let (_, rec) = decide_action_v2(ThreatType::Bullying, 0.6, ProtectionLevel::Medium);
        assert!(
            rec.follow_ups
                .contains(&FollowUpAction::MonitorConversation),
            "Bullying should recommend monitoring"
        );
    }

    #[test]
    fn manipulation_review_contact() {
        let (_, rec) = decide_action_v2(ThreatType::Manipulation, 0.7, ProtectionLevel::Medium);
        assert!(
            rec.follow_ups
                .contains(&FollowUpAction::ReviewContactProfile),
            "Manipulation should recommend reviewing contact"
        );
    }

    #[test]
    fn threat_block_suggested_at_80() {
        let (_, rec) = decide_action_v2(ThreatType::Threat, 0.85, ProtectionLevel::Medium);
        assert!(
            rec.follow_ups.contains(&FollowUpAction::BlockSuggested),
            "Threat ≥0.8 should suggest blocking"
        );
    }

    #[test]
    fn grooming_blocked_at_85() {
        let (action, _) = decide_action_v2(ThreatType::Grooming, 0.85, ProtectionLevel::Medium);
        assert_eq!(action, Action::Block, "Grooming ≥0.85 should be blocked");
    }

    #[test]
    fn no_crisis_resources_for_bullying() {
        let (_, rec) = decide_action_v2(ThreatType::Bullying, 0.9, ProtectionLevel::High);
        assert!(
            !rec.crisis_resources,
            "Bullying should not show crisis resources"
        );
    }

    #[test]
    fn pii_leakage_never_blocks() {
        let (action, _) = decide_action_v2(ThreatType::PiiLeakage, 0.95, ProtectionLevel::High);
        assert_ne!(
            action,
            Action::Block,
            "PII leakage must NEVER block (child is sharing, not attacking)"
        );
        assert_eq!(action, Action::Warn);
    }

    #[test]
    fn pii_leakage_warns_at_70() {
        let (action, _) = decide_action_v2(ThreatType::PiiLeakage, 0.7, ProtectionLevel::Medium);
        assert_eq!(action, Action::Warn, "PII ≥0.7 should warn");
    }

    #[test]
    fn pii_leakage_marks_at_40() {
        let (action, _) = decide_action_v2(ThreatType::PiiLeakage, 0.5, ProtectionLevel::Medium);
        assert_eq!(action, Action::Mark, "PII ≥0.4 should mark");
    }

    #[test]
    fn pii_leakage_parent_alert() {
        let (_, rec) = decide_action_v2(ThreatType::PiiLeakage, 0.6, ProtectionLevel::Medium);
        assert_eq!(
            rec.parent_alert,
            AlertPriority::High,
            "PII ≥0.5 should alert parent at High"
        );
        assert!(
            rec.follow_ups
                .contains(&FollowUpAction::ReviewContactProfile),
            "PII should recommend reviewing contact"
        );
    }
}
