use std::collections::HashMap;
use std::sync::Arc;

use crate::{
    DomainInput, DomainModule, DomainModuleId, DomainOutput, DomainTemporalInput,
    DomainTemporalOutput,
};

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

    pub fn register_arc<M>(&mut self, module: Arc<M>)
    where
        M: DomainModule + 'static,
    {
        self.modules.insert(module.id(), module);
    }

    pub fn contains(&self, module_id: DomainModuleId) -> bool {
        self.modules.contains_key(&module_id)
    }

    pub fn run(&self, module_id: DomainModuleId, input: &DomainInput) -> Option<DomainOutput> {
        let module = self.modules.get(&module_id)?;
        Some(module.analyze(input))
    }

    pub fn temporal_enabled(&self, module_id: DomainModuleId) -> bool {
        self.modules
            .get(&module_id)
            .is_some_and(|module| module.temporal_enabled())
    }

    pub fn run_temporal(
        &self,
        module_id: DomainModuleId,
        input: &DomainTemporalInput,
    ) -> Option<DomainTemporalOutput> {
        let module = self.modules.get(&module_id)?;
        Some(module.analyze_temporal(input))
    }
}

#[cfg(test)]
mod tests {
    use super::DomainRegistry;
    use crate::{
        DomainInput, DomainModule, DomainModuleId, DomainOutput, DomainTemporalInput,
        DomainTemporalOutput,
    };

    struct StatelessModule;

    impl DomainModule for StatelessModule {
        fn id(&self) -> DomainModuleId {
            DomainModuleId::Military
        }

        fn analyze(&self, _input: &DomainInput) -> DomainOutput {
            DomainOutput::default()
        }
    }

    #[test]
    fn stateless_module_keeps_temporal_path_disabled() {
        let mut registry = DomainRegistry::default();
        registry.register(StatelessModule);

        assert!(!registry.temporal_enabled(DomainModuleId::Military));
    }

    #[test]
    fn stateless_module_returns_empty_temporal_output() {
        let mut registry = DomainRegistry::default();
        registry.register(StatelessModule);
        let input = DomainTemporalInput {
            as_of_ms: 0,
            current_actor_id: 0,
            current_content_hash: None,
            conversation_type: Default::default(),
            events: Vec::new(),
        };

        let output = registry
            .run_temporal(DomainModuleId::Military, &input)
            .unwrap_or_else(DomainTemporalOutput::default);

        assert!(output.signals.is_empty());
    }
}
