use serde::{Deserialize, Serialize};

use crate::common::{Confidence, ThreatType};
use crate::context::ThreatContextFrame;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ConfirmedEvent {
    pub threat_type: ThreatType,
    #[serde(default)]
    pub score: f32,
    #[serde(default)]
    pub confidence: Confidence,
    #[serde(default)]
    pub context: ThreatContextFrame,
    #[serde(default)]
    pub reason_codes: Vec<String>,
    #[serde(default)]
    pub context_markers: Vec<String>,
}
