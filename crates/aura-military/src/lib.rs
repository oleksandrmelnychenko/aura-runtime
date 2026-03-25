pub mod detectors;
mod lexicon;
pub mod pipeline;
pub mod policy;

use aura_domain::{DomainInput, DomainModule, DomainModuleId, DomainOutput};

#[derive(Default)]
pub struct MilitaryModule;

impl DomainModule for MilitaryModule {
    fn id(&self) -> DomainModuleId {
        DomainModuleId::Military
    }

    fn analyze(&self, input: &DomainInput) -> DomainOutput {
        pipeline::run_military_pipeline(input)
    }
}
