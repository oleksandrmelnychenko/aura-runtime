use serde::{Deserialize, Serialize};

use crate::{DomainInput, DomainOutput, DomainTemporalInput, DomainTemporalOutput};

/// Stable identity used to select a registered domain module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainModuleId {
    /// Child and teen safety module.
    Kids,
    /// Military OPSEC and hostile-influence module.
    Military,
}

/// Thread-safe interface implemented by each domain-owned detector pipeline.
pub trait DomainModule: Send + Sync {
    /// Returns the module identity used by [`crate::DomainRegistry`].
    fn id(&self) -> DomainModuleId;
    /// Evaluates one bounded message projection.
    fn analyze(&self, input: &DomainInput) -> DomainOutput;

    /// Returns whether the module's temporal path is active for this build.
    fn temporal_enabled(&self) -> bool {
        false
    }

    /// Evaluates confirmed conversation history without persisting derived signals.
    fn analyze_temporal(&self, _input: &DomainTemporalInput) -> DomainTemporalOutput {
        DomainTemporalOutput::default()
    }
}
