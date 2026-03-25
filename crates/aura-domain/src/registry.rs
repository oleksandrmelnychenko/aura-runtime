use std::collections::HashMap;
use std::sync::Arc;

use crate::{DomainInput, DomainModule, DomainModuleId, DomainOutput};

#[derive(Default)]
pub struct DomainRegistry {
    modules: HashMap<DomainModuleId, Arc<dyn DomainModule>>,
}

impl DomainRegistry {
    pub fn register<M>(&mut self, module: M)
    where
        M: DomainModule + 'static,
    {
        self.modules.insert(module.id(), Arc::new(module));
    }

    pub fn contains(&self, module_id: DomainModuleId) -> bool {
        self.modules.contains_key(&module_id)
    }

    pub fn run(&self, module_id: DomainModuleId, input: &DomainInput) -> Option<DomainOutput> {
        let module = self.modules.get(&module_id)?;
        Some(module.analyze(input))
    }
}
