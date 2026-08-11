use std::collections::HashMap;
use std::sync::Arc;

use crate::{
    DomainConfirmedOutput, DomainInput, DomainModule, DomainModuleId, DomainOutput, DomainSignal,
    DomainTemporalInput, DomainTemporalOutput,
};

/// In-process map from stable module identities to thread-safe implementations.
#[derive(Default)]
pub struct DomainRegistry {
    modules: HashMap<DomainModuleId, Arc<dyn DomainModule>>,
}

impl DomainRegistry {
    /// Registers an owned module, replacing any implementation with the same id.
    pub fn register<M>(&mut self, module: M)
    where
        M: DomainModule + 'static,
    {
        self.modules.insert(module.id(), Arc::new(module));
    }

    /// Registers a shared module, replacing any implementation with the same id.
    pub fn register_arc<M>(&mut self, module: Arc<M>)
    where
        M: DomainModule + 'static,
    {
        self.modules.insert(module.id(), module);
    }

    /// Returns whether a module identity is registered.
    #[must_use]
    pub fn contains(&self, module_id: DomainModuleId) -> bool {
        self.modules.contains_key(&module_id)
    }

    /// Runs message analysis, or returns `None` when the module is absent.
    #[must_use]
    pub fn run(&self, module_id: DomainModuleId, input: &DomainInput) -> Option<DomainOutput> {
        let module = self.modules.get(&module_id)?;
        Some(module.analyze(input))
    }

    /// Runs candidate detection without allowing domain-owned memory mutation.
    #[must_use]
    pub fn run_detection(
        &self,
        module_id: DomainModuleId,
        input: &DomainInput,
    ) -> Option<DomainOutput> {
        let module = self.modules.get(&module_id)?;
        Some(module.detect(input))
    }

    /// Commits only signals accepted by the core interpretation boundary.
    #[must_use]
    pub fn commit_confirmed(
        &self,
        module_id: DomainModuleId,
        input: &DomainInput,
        confirmed_signals: &[DomainSignal],
    ) -> Option<DomainConfirmedOutput> {
        let module = self.modules.get(&module_id)?;
        Some(module.commit_confirmed(input, confirmed_signals))
    }

    /// Returns whether the registered module has enabled temporal analysis.
    #[must_use]
    pub fn temporal_enabled(&self, module_id: DomainModuleId) -> bool {
        self.modules
            .get(&module_id)
            .is_some_and(|module| module.temporal_enabled())
    }

    /// Runs enabled temporal analysis.
    ///
    /// Returns `None` when the module is absent or its temporal path is disabled.
    #[must_use]
    pub fn run_temporal(
        &self,
        module_id: DomainModuleId,
        input: &DomainTemporalInput,
    ) -> Option<DomainTemporalOutput> {
        let module = self.modules.get(&module_id)?;
        if !module.temporal_enabled() {
            return None;
        }
        Some(module.analyze_temporal(input))
    }
}

#[cfg(test)]
mod tests {
    use super::DomainRegistry;
    use crate::{
        DomainConversationType, DomainInput, DomainModule, DomainModuleId, DomainOutput,
        DomainTemporalInput,
    };

    struct StatelessModule;

    impl DomainModule for StatelessModule {
        fn id(&self) -> DomainModuleId {
            DomainModuleId::Military
        }

        fn detect(&self, _input: &DomainInput) -> DomainOutput {
            DomainOutput::default()
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
    fn stateless_module_cannot_run_disabled_temporal_path() {
        let mut registry = DomainRegistry::default();
        registry.register(StatelessModule);
        let input = DomainTemporalInput {
            as_of_ms: 0,
            current_actor_id: 0,
            current_content_hash: None,
            conversation_type: DomainConversationType::default(),
            events: Vec::new(),
        };

        let output = registry.run_temporal(DomainModuleId::Military, &input);

        assert!(output.is_none());
    }
}
