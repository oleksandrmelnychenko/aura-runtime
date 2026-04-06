use serde::{Deserialize, Serialize};

use crate::common::{Confidence, DetectionLayer, ThreatType};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct RawObservation {
    pub threat_type: ThreatType,
    #[serde(default)]
    pub threat_subtype: String,
    pub layer: DetectionLayer,
    #[serde(default)]
    pub score: f32,
    #[serde(default)]
    pub confidence: Confidence,
    #[serde(default)]
    pub reason_code: String,
    #[serde(default)]
    pub explanation: String,
}
