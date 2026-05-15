pub mod detectors;
mod lexicon;
pub mod pipeline;
pub mod policy;

use aura_domain::{DomainInput, DomainModule, DomainModuleId, DomainOutput};

#[derive(Default)]
pub struct KidsModule {
    memory: pipeline::KidsPipelineMemory,
}

impl KidsModule {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn export_memory(&self) -> pipeline::ExportedKidsMemoryState {
        pipeline::export_kids_memory_from(&self.memory)
    }

    pub fn import_memory(&self, state: &pipeline::ExportedKidsMemoryState) {
        pipeline::import_kids_memory_into(&self.memory, state);
    }

    pub fn clear_memory(&self) {
        pipeline::clear_kids_memory_in(&self.memory);
    }
}

impl DomainModule for KidsModule {
    fn id(&self) -> DomainModuleId {
        DomainModuleId::Kids
    }

    fn analyze(&self, input: &DomainInput) -> DomainOutput {
        pipeline::run_kids_pipeline_with_memory(input, &self.memory)
    }
}

#[cfg(test)]
mod tests {
    use super::KidsModule;
    use aura_domain::{
        DomainConversationType, DomainInput, DomainModule, DomainRiskProfile, DomainSignal,
    };

    fn input(text: &str) -> DomainInput {
        DomainInput {
            text: Some(text.to_string()),
            language: None,
            sender_id: Some("s1".to_string()),
            conversation_id: Some("conv_mem_gp".to_string()),
            risk_profile: DomainRiskProfile::Strict,
            conversation_type: DomainConversationType::Direct,
            ml_safety_hint: None,
            server_sender_risk_hint: None,
        }
    }

    fn has_reason(signals: &[DomainSignal], reason: &str) -> bool {
        signals.iter().any(|signal| signal.reason_code == reason)
    }

    #[test]
    fn module_instances_keep_memory_isolated() {
        let first = KidsModule::new();
        let second = KidsModule::new();
        let seed = input("our little secret. don't tell your parents.");
        let followup = input("you can only trust me. do it now or i post everything.");

        let _ = first.analyze(&seed);
        let first_output = first.analyze(&followup);
        let second_output = second.analyze(&followup);

        assert!(has_reason(
            &first_output.signals,
            "kids.memory.grooming_progression"
        ));
        assert!(!has_reason(
            &second_output.signals,
            "kids.memory.grooming_progression"
        ));
    }
}
