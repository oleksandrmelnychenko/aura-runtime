use std::sync::OnceLock;

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct DatasetSourceManifest {
    pub schema_version: u32,
    pub wave_id: String,
    pub updated_at: String,
    pub sources: Vec<DatasetSourceSpec>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct DatasetSourceSpec {
    pub source_family: String,
    pub upstream_dataset: String,
    pub threat_focus: Vec<String>,
    pub integration_targets: Vec<String>,
    pub minimum_quality: DatasetSourceQualitySpec,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct DatasetSourceQualitySpec {
    pub min_positive_detection_rate: f32,
    pub max_negative_false_positive_rate: f32,
    pub min_policy_scenario_pass_rate: f32,
    pub min_support_positive_scenarios: usize,
    pub min_support_negative_scenarios: usize,
}

pub fn wave1_dataset_source_manifest() -> &'static DatasetSourceManifest {
    static MANIFEST: OnceLock<DatasetSourceManifest> = OnceLock::new();
    MANIFEST.get_or_init(|| {
        let manifest = serde_json::from_str::<DatasetSourceManifest>(include_str!(
            "../data/dataset_source_manifest_wave1.json"
        ))
        .expect("valid wave1 dataset source manifest json");
        validate_dataset_manifest(&manifest).expect("valid wave1 dataset source manifest");
        manifest
    })
}

fn validate_dataset_manifest(manifest: &DatasetSourceManifest) -> Result<(), String> {
    if manifest.schema_version != 1 {
        return Err(format!(
            "unsupported dataset source manifest schema_version {}",
            manifest.schema_version
        ));
    }
    if manifest.wave_id.trim().is_empty() {
        return Err("dataset source manifest wave_id must not be empty".to_string());
    }
    if manifest.sources.is_empty() {
        return Err("dataset source manifest must contain at least one source".to_string());
    }

    for source in &manifest.sources {
        if source.source_family.trim().is_empty() {
            return Err("dataset source manifest source_family must not be empty".to_string());
        }
        if source.upstream_dataset.trim().is_empty() {
            return Err(format!(
                "dataset source {} has empty upstream_dataset",
                source.source_family
            ));
        }
        if source.threat_focus.is_empty() {
            return Err(format!(
                "dataset source {} has empty threat_focus",
                source.source_family
            ));
        }
        if source.integration_targets.is_empty() {
            return Err(format!(
                "dataset source {} has no integration_targets",
                source.source_family
            ));
        }
        validate_quality_thresholds(&source.source_family, &source.minimum_quality)?;
    }

    Ok(())
}

fn validate_quality_thresholds(
    source_family: &str,
    quality: &DatasetSourceQualitySpec,
) -> Result<(), String> {
    if !(0.0..=1.0).contains(&quality.min_positive_detection_rate) {
        return Err(format!(
            "dataset source {source_family} has invalid min_positive_detection_rate {}",
            quality.min_positive_detection_rate
        ));
    }
    if !(0.0..=1.0).contains(&quality.max_negative_false_positive_rate) {
        return Err(format!(
            "dataset source {source_family} has invalid max_negative_false_positive_rate {}",
            quality.max_negative_false_positive_rate
        ));
    }
    if !(0.0..=1.0).contains(&quality.min_policy_scenario_pass_rate) {
        return Err(format!(
            "dataset source {source_family} has invalid min_policy_scenario_pass_rate {}",
            quality.min_policy_scenario_pass_rate
        ));
    }
    if quality.min_support_positive_scenarios == 0 {
        return Err(format!(
            "dataset source {source_family} has zero min_support_positive_scenarios"
        ));
    }
    if quality.min_support_negative_scenarios == 0 {
        return Err(format!(
            "dataset source {source_family} has zero min_support_negative_scenarios"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn wave1_manifest_includes_required_source_families() {
        let manifest = wave1_dataset_source_manifest();
        let source_families = manifest
            .sources
            .iter()
            .map(|source| source.source_family.as_str())
            .collect::<BTreeSet<_>>();

        assert!(source_families.contains("bluff"));
        assert!(source_families.contains("mumin"));
        assert!(source_families.contains("ua_news"));
        assert!(source_families.contains("koalaai_text_moderation_multilingual"));
        assert!(source_families.contains("sensitive_content_classification"));
    }
}
