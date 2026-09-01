use aura_agent_ffi::release_runtime_artifact_digests;
use aura_patterns::PatternDatabase;
use aura_runtime::{AgentRuntime, AuraConfig, ProductRolloutMode, RuntimeBackend, RuntimeModality};

fn main() {
    let config = AuraConfig::default();
    let runtime = AgentRuntime::new(config, &PatternDatabase::default_mvp());
    let capabilities = runtime.runtime_capabilities();
    assert_eq!(capabilities.backend, RuntimeBackend::RulesFallback);
    assert_eq!(
        capabilities.supported_modalities,
        vec![RuntimeModality::Text, RuntimeModality::Url]
    );
    assert!(capabilities.models.is_empty());
    assert_eq!(
        capabilities.product_rollout_mode,
        ProductRolloutMode::Shadow
    );

    let (runtime_capabilities_digest, model_manifest_digest) =
        release_runtime_artifact_digests(&runtime);
    println!(
        "{} {} {} {}",
        hex_digest(&runtime_capabilities_digest),
        hex_digest(&model_manifest_digest),
        capabilities.runtime_version,
        capabilities.state_schema_version
    );
}

fn hex_digest(digest: &[u8; 32]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}
