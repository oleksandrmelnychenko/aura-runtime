use serde::{Deserialize, Serialize};

use crate::{DomainInput, DomainOutput, DomainTemporalInput, DomainTemporalOutput};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainModuleId {
    Kids,
    Military,
}

pub trait DomainModule: Send + Sync {
    fn id(&self) -> DomainModuleId;
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
