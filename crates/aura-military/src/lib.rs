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
#[cfg(feature = "shadow-telemetry")]
pub mod temporal_shadow_telemetry;

use aura_domain::{
    DomainInput, DomainModule, DomainModuleId, DomainOutput, DomainTemporalInput,
    DomainTemporalOutput,
};

#[derive(Default)]
pub struct MilitaryModule;

impl DomainModule for MilitaryModule {
    fn id(&self) -> DomainModuleId {
        DomainModuleId::Military
    }

    fn analyze(&self, input: &DomainInput) -> DomainOutput {
        pipeline::run_military_pipeline(input)
    }

    fn temporal_enabled(&self) -> bool {
        temporal::temporal_enabled()
    }

    fn analyze_temporal(&self, input: &DomainTemporalInput) -> DomainTemporalOutput {
        temporal::run_military_temporal_pipeline(input)
    }
}
