pub mod detectors;
mod lexicon;
pub mod pipeline;
pub mod policy;

use aura_domain::{DomainInput, DomainModule, DomainModuleId, DomainOutput};

#[derive(Default)]
pub struct KidsModule;

impl DomainModule for KidsModule {
    fn id(&self) -> DomainModuleId {
        DomainModuleId::Kids
    }

    fn analyze(&self, input: &DomainInput) -> DomainOutput {
        pipeline::run_kids_pipeline(input)
    }
}
