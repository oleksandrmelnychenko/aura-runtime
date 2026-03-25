use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Wave1DatasetSource {
    KoalaAiTextModerationMultilingual,
    SensitiveContentClassification,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Wave1TrainingExample {
    pub text: String,
    pub language: String,
    pub source: Wave1DatasetSource,
    pub bullying: f32,
    pub hate_speech: f32,
    pub explicit: f32,
    pub self_harm: f32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct KoalaAiRecord {
    text: String,
    language: String,
    #[serde(default)]
    labels: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
struct SensitiveContentRecord {
    text: String,
    language: String,
    #[serde(default)]
    bullying_score: Option<f32>,
    #[serde(default)]
    hate_score: Option<f32>,
    #[serde(default)]
    explicit_score: Option<f32>,
    #[serde(default)]
    self_harm_score: Option<f32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Wave1AdapterComparison {
    pub sample_count: usize,
    pub average_rule_only_score: f32,
    pub average_rule_plus_ml_score: f32,
    pub average_delta: f32,
}

pub fn parse_koalaai_adapter_records(json: &str) -> Result<Vec<Wave1TrainingExample>, String> {
    let records = serde_json::from_str::<Vec<KoalaAiRecord>>(json)
        .map_err(|err| format!("invalid koalaai adapter payload: {err}"))?;
    records
        .into_iter()
        .map(convert_koalaai_record)
        .collect::<Result<Vec<_>, _>>()
}

pub fn parse_sensitive_content_adapter_records(
    json: &str,
) -> Result<Vec<Wave1TrainingExample>, String> {
    let records = serde_json::from_str::<Vec<SensitiveContentRecord>>(json)
        .map_err(|err| format!("invalid sensitive-content adapter payload: {err}"))?;
    records
        .into_iter()
        .map(convert_sensitive_content_record)
        .collect::<Result<Vec<_>, _>>()
}

pub fn compare_rule_only_vs_rule_plus_ml(
    rule_only_scores: &[f32],
    rule_plus_ml_scores: &[f32],
) -> Result<Wave1AdapterComparison, String> {
    if rule_only_scores.len() != rule_plus_ml_scores.len() {
        return Err(format!(
            "score arrays must have same length: {} vs {}",
            rule_only_scores.len(),
            rule_plus_ml_scores.len()
        ));
    }
    if rule_only_scores.is_empty() {
        return Err("score arrays must not be empty".to_string());
    }

    let sample_count = rule_only_scores.len();
    let rule_only_sum = rule_only_scores.iter().copied().sum::<f32>();
    let rule_plus_ml_sum = rule_plus_ml_scores.iter().copied().sum::<f32>();
    let average_rule_only_score = rule_only_sum / sample_count as f32;
    let average_rule_plus_ml_score = rule_plus_ml_sum / sample_count as f32;

    Ok(Wave1AdapterComparison {
        sample_count,
        average_rule_only_score,
        average_rule_plus_ml_score,
        average_delta: average_rule_plus_ml_score - average_rule_only_score,
    })
}

fn convert_koalaai_record(record: KoalaAiRecord) -> Result<Wave1TrainingExample, String> {
    if record.text.trim().is_empty() {
        return Err("koalaai record text must not be empty".to_string());
    }
    if record.language.trim().is_empty() {
        return Err("koalaai record language must not be empty".to_string());
    }

    let has_label = |label: &str| record.labels.iter().any(|value| value == label);
    Ok(Wave1TrainingExample {
        text: record.text,
        language: record.language,
        source: Wave1DatasetSource::KoalaAiTextModerationMultilingual,
        bullying: f32::from(has_label("bullying")),
        hate_speech: f32::from(has_label("hate_speech")),
        explicit: f32::from(has_label("explicit")),
        self_harm: f32::from(has_label("self_harm")),
    })
}

fn convert_sensitive_content_record(
    record: SensitiveContentRecord,
) -> Result<Wave1TrainingExample, String> {
    if record.text.trim().is_empty() {
        return Err("sensitive-content record text must not be empty".to_string());
    }
    if record.language.trim().is_empty() {
        return Err("sensitive-content record language must not be empty".to_string());
    }

    Ok(Wave1TrainingExample {
        text: record.text,
        language: record.language,
        source: Wave1DatasetSource::SensitiveContentClassification,
        bullying: record.bullying_score.unwrap_or(0.0).clamp(0.0, 1.0),
        hate_speech: record.hate_score.unwrap_or(0.0).clamp(0.0, 1.0),
        explicit: record.explicit_score.unwrap_or(0.0).clamp(0.0, 1.0),
        self_harm: record.self_harm_score.unwrap_or(0.0).clamp(0.0, 1.0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn koalaai_adapter_maps_multilabel_records() {
        let payload = r#"
        [
          {"text":"you are worthless", "language":"en", "labels":["bullying","hate_speech"]},
          {"text":"не хочу жити", "language":"uk", "labels":["self_harm"]}
        ]
        "#;
        let rows = parse_koalaai_adapter_records(payload).expect("koalaai rows");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].bullying, 1.0);
        assert_eq!(rows[0].hate_speech, 1.0);
        assert_eq!(rows[1].self_harm, 1.0);
    }

    #[test]
    fn sensitive_content_adapter_preserves_probabilities() {
        let payload = r#"
        [
          {
            "text":"send nudes now",
            "language":"en",
            "explicit_score":0.95,
            "bullying_score":0.02,
            "hate_score":0.01,
            "self_harm_score":0.0
          }
        ]
        "#;
        let rows = parse_sensitive_content_adapter_records(payload).expect("sensitive rows");
        assert_eq!(rows.len(), 1);
        assert!(rows[0].explicit > 0.9);
        assert!(rows[0].bullying < 0.1);
    }

    #[test]
    fn comparison_report_computes_average_delta() {
        let report = compare_rule_only_vs_rule_plus_ml(&[0.55, 0.60], &[0.65, 0.78])
            .expect("comparison report");
        assert_eq!(report.sample_count, 2);
        assert!(report.average_rule_plus_ml_score > report.average_rule_only_score);
        assert!(report.average_delta > 0.0);
    }
}
