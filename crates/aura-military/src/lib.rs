pub mod detectors;
mod lexicon;
pub mod pipeline;
pub mod policy;
mod routing;
mod temporal;
mod text;

#[cfg(feature = "evaluation")]
pub mod temporal_eval;
#[cfg(feature = "evaluation")]
pub mod temporal_review;
#[cfg(feature = "evaluation")]
pub mod temporal_review_packet;
#[cfg(feature = "shadow-telemetry")]
pub mod temporal_shadow_telemetry;
#[cfg(feature = "evaluation")]
pub mod temporal_study;

use aura_domain::{
    DomainConfirmedOutput, DomainInput, DomainModule, DomainModuleId, DomainOutput, DomainSignal,
    DomainTemporalInput, DomainTemporalOutput,
};

#[derive(Default)]
pub struct MilitaryModule;

impl DomainModule for MilitaryModule {
    fn id(&self) -> DomainModuleId {
        DomainModuleId::Military
    }

    fn detect(&self, input: &DomainInput) -> DomainOutput {
        pipeline::run_military_pipeline(input)
    }

    fn analyze(&self, input: &DomainInput) -> DomainOutput {
        pipeline::run_military_pipeline(input)
    }

    fn commit_confirmed(
        &self,
        _input: &DomainInput,
        confirmed_signals: &[DomainSignal],
    ) -> DomainConfirmedOutput {
        pipeline::commit_confirmed_military_pipeline(confirmed_signals)
    }

    fn temporal_enabled(&self) -> bool {
        temporal::temporal_enabled()
    }

    fn analyze_temporal(&self, input: &DomainTemporalInput) -> DomainTemporalOutput {
        temporal::run_military_temporal_pipeline(input)
    }
}
