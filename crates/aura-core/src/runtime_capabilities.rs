//! Read-only description of an initialized AURA runtime.

use serde::{Deserialize, Serialize};

use crate::product::ProductRolloutMode;

/// Schema version of [`RuntimeCapabilities`].
pub const RUNTIME_CAPABILITIES_SCHEMA_VERSION: &str = "aura.runtime_capabilities.v1";

/// Inference implementation that is actually active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeBackend {
    RulesFallback,
    Onnx,
}

/// Input modality implemented by the runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeModality {
    Text,
    Url,
}

/// Identity of a model that was successfully loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeModelIdentity {
    pub component: String,
    pub identifier: String,
    /// SHA-256 is absent unless the runtime can attest the loaded artifact.
    pub sha256: Option<String>,
}

/// Versioned capabilities of one initialized runtime instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCapabilities {
    pub schema_version: String,
    pub runtime_version: String,
    pub backend: RuntimeBackend,
    pub supported_modalities: Vec<RuntimeModality>,
    pub models: Vec<RuntimeModelIdentity>,
    pub policy_schema_version: String,
    pub product_schema_version: String,
    pub state_schema_version: u32,
    pub product_rollout_mode: ProductRolloutMode,
}
