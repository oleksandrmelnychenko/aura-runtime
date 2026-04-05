use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DomainRiskProfile {
    #[default]
    Normal,
    Strict,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DomainConversationType {
    #[default]
    Direct,
    Group,
}

/// ML safety scores passed as hints from the ML pipeline to domain modules.
///
/// Allows domain modules (e.g., aura-kids) to incorporate ML confidence
/// into their conversation memory and escalation logic even when no
/// lexicon rule fires.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct MlSafetyHint {
    pub grooming: f32,
    pub bullying: f32,
    pub self_harm: f32,
    pub manipulation: f32,
}

impl MlSafetyHint {
    pub fn has_any_signal(&self, threshold: f32) -> bool {
        self.grooming >= threshold
            || self.bullying >= threshold
            || self.self_harm >= threshold
            || self.manipulation >= threshold
    }

    pub fn max_score(&self) -> f32 {
        self.grooming
            .max(self.bullying)
            .max(self.self_harm)
            .max(self.manipulation)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainInput {
    pub text: Option<String>,
    pub language: Option<String>,
    pub sender_id: Option<String>,
    pub conversation_id: Option<String>,
    #[serde(default)]
    pub risk_profile: DomainRiskProfile,
    #[serde(default)]
    pub conversation_type: DomainConversationType,
    /// ML safety scores from the unified model, if available.
    /// Domain modules use these to feed sub-threshold ML detections
    /// into conversation memory for trend tracking.
    #[serde(default)]
    pub ml_safety_hint: Option<MlSafetyHint>,
    /// Server-injected sender reputation hint (0.0 = unknown, 1.0 = max risk).
    #[serde(default)]
    pub server_sender_risk_hint: Option<f32>,
}
