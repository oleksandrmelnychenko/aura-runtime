use serde::{Deserialize, Serialize};

use crate::{
    DomainConfirmedOutput, DomainInput, DomainOutput, DomainSignal, DomainTemporalInput,
    DomainTemporalOutput,
};

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
    /// Detects candidate signals without mutating domain-owned memory.
    ///
    /// Stateless and legacy modules inherit the standalone analysis path for
    /// source compatibility. Stateful modules must override this method with
    /// a non-mutating pass to satisfy the integrated runtime contract.
    fn detect(&self, input: &DomainInput) -> DomainOutput {
        self.analyze(input)
    }

    /// Evaluates one bounded message projection through the module's standalone path.
    ///
    /// Stateful implementations may preserve their direct crate API here. The
    /// integrated runtime uses [`Self::detect`] followed by
    /// [`Self::commit_confirmed`] so unconfirmed observations cannot mutate
    /// memory.
    fn analyze(&self, input: &DomainInput) -> DomainOutput;

    /// Commits only interpreter-confirmed source signals and returns memory derivatives.
    fn commit_confirmed(
        &self,
        _input: &DomainInput,
        confirmed_signals: &[DomainSignal],
    ) -> DomainConfirmedOutput {
        DomainConfirmedOutput {
            confirmed_signals: confirmed_signals.to_vec(),
            derived_signals: Vec::new(),
            action: None,
        }
    }

    /// Returns whether the module's temporal path is active for this build.
    fn temporal_enabled(&self) -> bool {
        false
    }

    /// Evaluates confirmed conversation history without persisting derived signals.
    fn analyze_temporal(&self, _input: &DomainTemporalInput) -> DomainTemporalOutput {
        DomainTemporalOutput::default()
    }
}
