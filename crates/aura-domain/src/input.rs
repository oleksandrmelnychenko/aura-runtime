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
}
