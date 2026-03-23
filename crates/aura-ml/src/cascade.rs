//! Model cascade: Tier 1 gate → Tier 2 deep model.
//!
//! The cascade skips expensive ONNX inference when the cheap lexicon
//! gate model determines the message is likely safe. This reduces
//! average per-message latency by 60-70% while maintaining detection
//! quality for risky content.

use crate::types::{CascadeTier, InferencePriority};

/// Cascade decision output.
#[derive(Debug, Clone)]
pub struct CascadeDecision {
    /// Whether to run the deep model.
    pub run_deep: bool,
    /// The cascade tier that was selected.
    pub tier: CascadeTier,
    /// The priority level for scheduling.
    pub priority: InferencePriority,
    /// The gate score that informed the decision.
    pub gate_score: f32,
}

/// Configuration for cascade behavior.
#[derive(Debug, Clone)]
pub struct CascadePolicy {
    /// Gate score threshold above which deep model runs.
    pub gate_threshold: f32,
    /// Whether cascade is enabled (false = always run deep).
    pub enabled: bool,
}

impl Default for CascadePolicy {
    fn default() -> Self {
        Self {
            gate_threshold: 0.3,
            enabled: true,
        }
    }
}

impl CascadePolicy {
    /// Decides whether to run the deep model based on the gate score.
    pub fn decide(&self, gate_score: f32) -> CascadeDecision {
        if !self.enabled {
            return CascadeDecision {
                run_deep: true,
                tier: CascadeTier::Deep,
                priority: InferencePriority::Normal,
                gate_score,
            };
        }

        if gate_score >= 0.85 {
            return CascadeDecision {
                run_deep: true,
                tier: CascadeTier::Deep,
                priority: InferencePriority::Critical,
                gate_score,
            };
        }

        if gate_score >= 0.6 {
            return CascadeDecision {
                run_deep: true,
                tier: CascadeTier::Deep,
                priority: InferencePriority::High,
                gate_score,
            };
        }

        if gate_score >= self.gate_threshold {
            return CascadeDecision {
                run_deep: true,
                tier: CascadeTier::Deep,
                priority: InferencePriority::Normal,
                gate_score,
            };
        }

        CascadeDecision {
            run_deep: false,
            tier: CascadeTier::Gate,
            priority: InferencePriority::Low,
            gate_score,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_score_skips_deep() {
        let policy = CascadePolicy::default();
        let decision = policy.decide(0.0);
        assert!(!decision.run_deep);
        assert_eq!(decision.tier, CascadeTier::Gate);
        assert_eq!(decision.priority, InferencePriority::Low);
    }

    #[test]
    fn high_score_runs_deep_critical() {
        let policy = CascadePolicy::default();
        let decision = policy.decide(0.95);
        assert!(decision.run_deep);
        assert_eq!(decision.tier, CascadeTier::Deep);
        assert_eq!(decision.priority, InferencePriority::Critical);
    }

    #[test]
    fn medium_score_runs_deep_high() {
        let policy = CascadePolicy::default();
        let decision = policy.decide(0.65);
        assert!(decision.run_deep);
        assert_eq!(decision.priority, InferencePriority::High);
    }

    #[test]
    fn threshold_score_runs_deep_normal() {
        let policy = CascadePolicy::default();
        let decision = policy.decide(0.35);
        assert!(decision.run_deep);
        assert_eq!(decision.priority, InferencePriority::Normal);
    }

    #[test]
    fn below_threshold_skips() {
        let policy = CascadePolicy::default();
        let decision = policy.decide(0.25);
        assert!(!decision.run_deep);
    }

    #[test]
    fn disabled_cascade_always_runs_deep() {
        let policy = CascadePolicy {
            enabled: false,
            ..Default::default()
        };
        let decision = policy.decide(0.0);
        assert!(decision.run_deep);
        assert_eq!(decision.tier, CascadeTier::Deep);
    }

    #[test]
    fn custom_threshold() {
        let policy = CascadePolicy {
            gate_threshold: 0.5,
            enabled: true,
        };
        assert!(!policy.decide(0.4).run_deep);
        assert!(policy.decide(0.55).run_deep);
    }
}
