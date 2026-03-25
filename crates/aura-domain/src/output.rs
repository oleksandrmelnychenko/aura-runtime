use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainAction {
    Allow,
    Mark,
    Warn,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainSignal {
    pub threat_key: String,
    pub score: f32,
    pub reason_code: String,
    #[serde(default)]
    pub threat_type: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub priority: Option<u8>,
    #[serde(default)]
    pub action: Option<DomainAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainOutput {
    pub signals: Vec<DomainSignal>,
    pub action: Option<DomainAction>,
}
