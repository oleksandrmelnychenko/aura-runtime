use std::collections::{BTreeMap, BTreeSet};

use aura_core::{
    predicted_score_for_threat, AccountType, Action, AnalysisResult, Analyzer, AuraConfig,
    ContentType, ConversationType, DetectionLayer, DomainMode, MessageInput, ProtectionLevel,
    RuntimeCapabilities, ThreatType,
};
use aura_patterns::PatternDatabase;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const FIXTURE: &str = include_str!(
    "../../../experiments/client-detector-logic/data/client_detector_logic_cases_v1.json"
);
const FIXED_COMMIT: &str = "4580e602639970fb936b46d43a6c366985ea3b39";
const FIXED_PRE_EXPERIMENT_DIFF_SHA256: &str =
    "49464eb6a5b3df5852d4fe100589951212d897dab367e29101b3b0081e1fad74";

const ALL_THREATS: [ThreatType; 18] = [
    ThreatType::Bullying,
    ThreatType::Grooming,
    ThreatType::Explicit,
    ThreatType::Threat,
    ThreatType::SelfHarm,
    ThreatType::Spam,
    ThreatType::Scam,
    ThreatType::Phishing,
    ThreatType::Manipulation,
    ThreatType::Nsfw,
    ThreatType::HateSpeech,
    ThreatType::Doxxing,
    ThreatType::PiiLeakage,
    ThreatType::Propaganda,
    ThreatType::OpsecViolation,
    ThreatType::Psyops,
    ThreatType::MilitarySocialEng,
    ThreatType::CoordinateLeak,
];

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u32,
    dataset_id: String,
    review_status: String,
    cases: Vec<Case>,
    metamorphic_seeds: Vec<MetamorphicSeed>,
}

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    pair_id: String,
    language: String,
    cohort: String,
    expected_threat: Option<ThreatType>,
    text: String,
}

#[derive(Debug, Deserialize)]
struct MetamorphicSeed {
    id: String,
    language: String,
    expected_threat: ThreatType,
    text: String,
}

#[derive(Debug, Clone, Serialize)]
struct Proportion {
    numerator: usize,
    denominator: usize,
    value: f64,
    wilson_95_low: f64,
    wilson_95_high: f64,
}

#[derive(Debug, Clone, Default)]
struct Counts {
    positive: usize,
    positive_detected: usize,
    exact_family: usize,
    safe: usize,
    safe_false_positive: usize,
    positive_allow_errors: usize,
    safe_block_errors: usize,
}

#[derive(Debug, Clone, Serialize)]
struct MetricSet {
    positive_recall: Proportion,
    expected_family_accuracy: Proportion,
    safe_false_positive_rate: Proportion,
    safe_specificity: Proportion,
    positive_allow_errors: usize,
    safe_block_errors: usize,
}

#[derive(Debug, Serialize)]
struct LayerCounts {
    pattern_matching: usize,
    ml_classification: usize,
    context_analysis: usize,
}

#[derive(Debug, Serialize)]
struct CaseResult {
    id: String,
    pair_id: String,
    language: String,
    cohort: String,
    expected_threat: Option<ThreatType>,
    operating_prediction: Option<ThreatType>,
    client_primary: ThreatType,
    client_primary_score: f32,
    expected_score: Option<f32>,
    expected_detected: bool,
    any_alert: bool,
    exact_family: bool,
    action: Action,
    action_error: bool,
    reason_codes: Vec<String>,
    layers: LayerCounts,
    analysis_time_us: u64,
}

#[derive(Debug, Serialize)]
struct SliceResult {
    slice: String,
    support: usize,
    metrics: MetricSet,
}

#[derive(Debug, Serialize)]
struct PairSummary {
    total_pairs: usize,
    correct_pairs: usize,
    pair_accuracy: Proportion,
    failed_pair_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct MetamorphicResult {
    seed_id: String,
    language: String,
    expected_threat: ThreatType,
    transform: String,
    expected_score: f32,
    detected: bool,
    operating_prediction: Option<ThreatType>,
    client_primary: ThreatType,
    action: Action,
    reason_codes: Vec<String>,
    analysis_time_us: u64,
}

#[derive(Debug, Serialize)]
struct MetamorphicTransformSummary {
    transform: String,
    detected: Proportion,
    failed_case_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct MetamorphicSummary {
    seed_detection: Proportion,
    variant_detection: Proportion,
    decision_preservation_from_detected_seeds: Proportion,
    by_transform: Vec<MetamorphicTransformSummary>,
    failed_seed_ids: Vec<String>,
    failed_variant_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct LatencySummary {
    count: usize,
    median_us: u64,
    p95_us: u64,
    max_us: u64,
}

#[derive(Debug, Serialize)]
struct ExperimentReport {
    schema_version: String,
    protocol: String,
    implementation: ImplementationIdentity,
    dataset: DatasetIdentity,
    runtime: RuntimeCapabilities,
    thresholds: BTreeMap<String, f32>,
    overall: MetricSet,
    pair_summary: PairSummary,
    by_language: Vec<SliceResult>,
    by_expected_threat: Vec<SliceResult>,
    confusion_matrix: BTreeMap<String, BTreeMap<String, usize>>,
    layer_counts: BTreeMap<String, usize>,
    reason_code_counts: BTreeMap<String, usize>,
    failed_case_ids: Vec<String>,
    metamorphic: MetamorphicSummary,
    latency: LatencySummary,
    cases: Vec<CaseResult>,
    metamorphic_cases: Vec<MetamorphicResult>,
    interpretation_limits: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ImplementationIdentity {
    fixed_commit: String,
    fixed_pre_experiment_diff_sha256: String,
}

#[derive(Debug, Serialize)]
struct DatasetIdentity {
    schema_version: u32,
    dataset_id: String,
    review_status: String,
    sha256: String,
    pair_case_count: usize,
    metamorphic_seed_count: usize,
}

fn main() {
    let fixture: Fixture = serde_json::from_str(FIXTURE).expect("valid experiment fixture");
    validate_fixture(&fixture);

    let db = PatternDatabase::default_mvp();
    let mut analyzers = analyzers_by_language(&db, ["en", "uk", "ru"]);
    let runtime = analyzers
        .get("en")
        .expect("English analyzer")
        .runtime_capabilities();

    let mut case_results = Vec::with_capacity(fixture.cases.len());
    for case in &fixture.cases {
        let analyzer = analyzers
            .get_mut(case.language.as_str())
            .expect("fixture language analyzer");
        analyzer.reset_runtime_state();
        let result = analyzer.analyze(&message(&case.id, &case.language, &case.text));
        case_results.push(evaluate_case(case, &result));
    }

    let metamorphic_cases = run_metamorphic(&fixture.metamorphic_seeds, &mut analyzers);
    let overall_counts = counts_for_cases(&case_results);
    let overall = metric_set(&overall_counts);
    let pair_summary = summarize_pairs(&case_results);
    let by_language = summarize_slices(
        &case_results,
        case_results.iter().map(|case| case.language.clone()),
        |case, key| case.language == key,
    );
    let by_expected_threat = summarize_slices(
        &case_results,
        case_results
            .iter()
            .map(|case| expected_label(case.expected_threat)),
        |case, key| expected_label(case.expected_threat) == key,
    );
    let confusion_matrix = build_confusion_matrix(&case_results);
    let (layer_counts, reason_code_counts) = aggregate_diagnostics(&case_results);
    let failed_case_ids = case_results
        .iter()
        .filter(|case| case_failed(case))
        .map(|case| case.id.clone())
        .collect();
    let metamorphic = summarize_metamorphic(&fixture.metamorphic_seeds, &metamorphic_cases);
    let latency = latency_summary(
        case_results
            .iter()
            .map(|case| case.analysis_time_us)
            .chain(metamorphic_cases.iter().map(|case| case.analysis_time_us))
            .collect(),
    );

    let report = ExperimentReport {
        schema_version: "aura.client_detector_logic_experiment.v1".to_string(),
        protocol: "docs/client-detector-logic-experiment-v1.md".to_string(),
        implementation: ImplementationIdentity {
            fixed_commit: FIXED_COMMIT.to_string(),
            fixed_pre_experiment_diff_sha256: FIXED_PRE_EXPERIMENT_DIFF_SHA256.to_string(),
        },
        dataset: DatasetIdentity {
            schema_version: fixture.schema_version,
            dataset_id: fixture.dataset_id,
            review_status: fixture.review_status,
            sha256: sha256_hex(FIXTURE.as_bytes()),
            pair_case_count: fixture.cases.len(),
            metamorphic_seed_count: fixture.metamorphic_seeds.len(),
        },
        runtime,
        thresholds: threshold_manifest(),
        overall,
        pair_summary,
        by_language,
        by_expected_threat,
        confusion_matrix,
        layer_counts,
        reason_code_counts,
        failed_case_ids,
        metamorphic,
        latency,
        cases: case_results,
        metamorphic_cases,
        interpretation_limits: vec![
            "Developer-authored counterfactuals are mechanistic tests, not an independent field-accuracy estimate.".to_string(),
            "The current checkout has no governed ONNX model artifacts; this report describes the active fallback runtime.".to_string(),
            "No threshold or detector tuning was performed after observing this custom run.".to_string(),
        ],
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serializable report")
    );
}

fn validate_fixture(fixture: &Fixture) {
    assert_eq!(fixture.schema_version, 1, "known fixture schema");
    let mut ids = BTreeSet::new();
    let mut pairs: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for case in &fixture.cases {
        assert!(
            ids.insert(case.id.as_str()),
            "duplicate case id {}",
            case.id
        );
        assert!(matches!(case.language.as_str(), "en" | "uk" | "ru"));
        assert!(matches!(case.cohort.as_str(), "risky" | "safe"));
        assert_eq!(case.cohort == "risky", case.expected_threat.is_some());
        pairs
            .entry(case.pair_id.as_str())
            .or_default()
            .push(case.cohort.as_str());
    }
    for (pair_id, cohorts) in pairs {
        assert_eq!(cohorts.len(), 2, "pair {pair_id} must have two cases");
        assert!(cohorts.contains(&"risky"), "pair {pair_id} missing risky");
        assert!(cohorts.contains(&"safe"), "pair {pair_id} missing safe");
    }
}

fn analyzers_by_language<'a>(
    db: &'a PatternDatabase,
    languages: impl IntoIterator<Item = &'a str>,
) -> BTreeMap<String, Analyzer> {
    languages
        .into_iter()
        .map(|language| {
            let config = AuraConfig {
                account_type: AccountType::Child,
                protection_level: ProtectionLevel::High,
                domain_mode: DomainMode::Kids,
                language: language.to_string(),
                account_holder_age: Some(12),
                ..AuraConfig::default()
            };
            (language.to_string(), Analyzer::new(config, db))
        })
        .collect()
}

fn message(id: &str, language: &str, text: &str) -> MessageInput {
    MessageInput {
        content_type: ContentType::Text,
        text: Some(text.to_string()),
        image_data: None,
        sender_id: format!("sender_{id}").into(),
        conversation_id: format!("conversation_{id}").into(),
        language: Some(language.to_string()),
        language_evidence: None,
        conversation_type: ConversationType::Direct,
        member_count: None,
        sender_relationship: Default::default(),
        relationship_trust_source: Default::default(),
    }
}

fn evaluate_case(case: &Case, result: &AnalysisResult) -> CaseResult {
    let operating_prediction = operating_prediction(result);
    let expected_score = case
        .expected_threat
        .map(|expected| predicted_score_for_threat(result, expected));
    let expected_detected = case
        .expected_threat
        .is_some_and(|expected| expected_score.unwrap_or_default() >= threshold(expected));
    let any_alert = operating_prediction.is_some();
    let exact_family = case
        .expected_threat
        .is_some_and(|expected| operating_prediction == Some(expected));
    let action_error = if case.expected_threat.is_some() {
        result.action == Action::Allow
    } else {
        result.action == Action::Block
    };

    CaseResult {
        id: case.id.clone(),
        pair_id: case.pair_id.clone(),
        language: case.language.clone(),
        cohort: case.cohort.clone(),
        expected_threat: case.expected_threat,
        operating_prediction,
        client_primary: result.threat_type,
        client_primary_score: result.score,
        expected_score,
        expected_detected,
        any_alert,
        exact_family,
        action: result.action,
        action_error,
        reason_codes: result.reason_codes.clone(),
        layers: layer_counts(&result.signals),
        analysis_time_us: result.analysis_time_us,
    }
}

fn run_metamorphic(
    seeds: &[MetamorphicSeed],
    analyzers: &mut BTreeMap<String, Analyzer>,
) -> Vec<MetamorphicResult> {
    let mut results = Vec::new();
    for seed in seeds {
        let mut variants = vec![("base", seed.text.clone())];
        variants.extend(transforms(&seed.text, &seed.language));
        for (transform, text) in variants {
            let id = format!("{}::{transform}", seed.id);
            let analyzer = analyzers
                .get_mut(seed.language.as_str())
                .expect("metamorphic language analyzer");
            analyzer.reset_runtime_state();
            let result = analyzer.analyze(&message(&id, &seed.language, &text));
            let expected_score = predicted_score_for_threat(&result, seed.expected_threat);
            results.push(MetamorphicResult {
                seed_id: seed.id.clone(),
                language: seed.language.clone(),
                expected_threat: seed.expected_threat,
                transform: transform.to_string(),
                expected_score,
                detected: expected_score >= threshold(seed.expected_threat),
                operating_prediction: operating_prediction(&result),
                client_primary: result.threat_type,
                action: result.action,
                reason_codes: result.reason_codes,
                analysis_time_us: result.analysis_time_us,
            });
        }
    }
    results
}

fn transforms(text: &str, language: &str) -> Vec<(&'static str, String)> {
    let mut transformed = vec![
        ("case", text.to_uppercase()),
        ("zero_width", intersperse_inside_words(text, '\u{200b}')),
        ("punctuation", intersperse_inside_words(text, '·')),
        ("confusable", replace_first_confusable(text)),
        ("combining_mark", add_combining_mark(text)),
    ];
    if language == "en" {
        transformed.push(("compatibility_fullwidth", ascii_fullwidth(text)));
    }
    transformed
}

fn intersperse_inside_words(text: &str, separator: char) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut output = String::with_capacity(text.len() * 2);
    for (index, ch) in chars.iter().copied().enumerate() {
        output.push(ch);
        if ch.is_alphanumeric()
            && chars
                .get(index + 1)
                .is_some_and(|next| next.is_alphanumeric())
        {
            output.push(separator);
        }
    }
    output
}

fn replace_first_confusable(text: &str) -> String {
    let mut replaced = false;
    text.chars()
        .map(|ch| {
            if replaced {
                return ch;
            }
            let replacement = match ch {
                'a' => 'а',
                'c' => 'с',
                'e' => 'е',
                'o' => 'о',
                'p' => 'р',
                'x' => 'х',
                'y' => 'у',
                'A' => 'А',
                'C' => 'С',
                'E' => 'Е',
                'O' => 'О',
                'P' => 'Р',
                'X' => 'Х',
                'а' => 'a',
                'с' => 'c',
                'е' => 'e',
                'о' => 'o',
                'р' => 'p',
                'х' => 'x',
                'у' => 'y',
                'і' => 'i',
                'А' => 'A',
                'С' => 'C',
                'Е' => 'E',
                'О' => 'O',
                'Р' => 'P',
                'Х' => 'X',
                'І' => 'I',
                _ => return ch,
            };
            replaced = true;
            replacement
        })
        .collect()
}

fn add_combining_mark(text: &str) -> String {
    let mut output = String::with_capacity(text.len() + 8);
    for ch in text.chars() {
        output.push(ch);
        if matches!(ch.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u' | 'y')
            || matches!(
                ch,
                'а' | 'е'
                    | 'є'
                    | 'и'
                    | 'і'
                    | 'ї'
                    | 'о'
                    | 'у'
                    | 'ю'
                    | 'я'
                    | 'А'
                    | 'Е'
                    | 'Є'
                    | 'И'
                    | 'І'
                    | 'Ї'
                    | 'О'
                    | 'У'
                    | 'Ю'
                    | 'Я'
            )
        {
            output.push('\u{0301}');
        }
    }
    output
}

fn ascii_fullwidth(text: &str) -> String {
    text.chars()
        .map(|ch| match ch {
            '!'..='~' => char::from_u32(ch as u32 + 0xfee0).expect("fullwidth ASCII mapping"),
            _ => ch,
        })
        .collect()
}

fn operating_prediction(result: &AnalysisResult) -> Option<ThreatType> {
    ALL_THREATS
        .iter()
        .copied()
        .filter_map(|threat| {
            let score = predicted_score_for_threat(result, threat);
            (score >= threshold(threat)).then_some((threat, score))
        })
        .max_by(|(_, left), (_, right)| left.total_cmp(right))
        .map(|(threat, _)| threat)
}

fn threshold(threat: ThreatType) -> f32 {
    match threat {
        ThreatType::SelfHarm => 0.70,
        ThreatType::Threat => 0.60,
        ThreatType::None => f32::INFINITY,
        _ => 0.55,
    }
}

fn threshold_manifest() -> BTreeMap<String, f32> {
    ALL_THREATS
        .iter()
        .copied()
        .map(|threat| (threat_label(threat), threshold(threat)))
        .collect()
}

fn counts_for_cases(cases: &[CaseResult]) -> Counts {
    let mut counts = Counts::default();
    for case in cases {
        if case.expected_threat.is_some() {
            counts.positive += 1;
            counts.positive_detected += usize::from(case.expected_detected);
            counts.exact_family += usize::from(case.exact_family);
            counts.positive_allow_errors += usize::from(case.action == Action::Allow);
        } else {
            counts.safe += 1;
            counts.safe_false_positive += usize::from(case.any_alert);
            counts.safe_block_errors += usize::from(case.action == Action::Block);
        }
    }
    counts
}

fn metric_set(counts: &Counts) -> MetricSet {
    MetricSet {
        positive_recall: proportion(counts.positive_detected, counts.positive),
        expected_family_accuracy: proportion(counts.exact_family, counts.positive),
        safe_false_positive_rate: proportion(counts.safe_false_positive, counts.safe),
        safe_specificity: proportion(
            counts.safe.saturating_sub(counts.safe_false_positive),
            counts.safe,
        ),
        positive_allow_errors: counts.positive_allow_errors,
        safe_block_errors: counts.safe_block_errors,
    }
}

fn summarize_slices<I, F>(cases: &[CaseResult], keys: I, includes: F) -> Vec<SliceResult>
where
    I: IntoIterator<Item = String>,
    F: Fn(&CaseResult, &str) -> bool,
{
    let keys: BTreeSet<String> = keys.into_iter().collect();
    keys.into_iter()
        .map(|key| {
            let selected: Vec<_> = cases.iter().filter(|case| includes(case, &key)).collect();
            let owned: Vec<CaseResult> = selected
                .iter()
                .map(|case| clone_case_result(case))
                .collect();
            SliceResult {
                slice: key,
                support: owned.len(),
                metrics: metric_set(&counts_for_cases(&owned)),
            }
        })
        .collect()
}

fn clone_case_result(case: &CaseResult) -> CaseResult {
    CaseResult {
        id: case.id.clone(),
        pair_id: case.pair_id.clone(),
        language: case.language.clone(),
        cohort: case.cohort.clone(),
        expected_threat: case.expected_threat,
        operating_prediction: case.operating_prediction,
        client_primary: case.client_primary,
        client_primary_score: case.client_primary_score,
        expected_score: case.expected_score,
        expected_detected: case.expected_detected,
        any_alert: case.any_alert,
        exact_family: case.exact_family,
        action: case.action,
        action_error: case.action_error,
        reason_codes: case.reason_codes.clone(),
        layers: LayerCounts {
            pattern_matching: case.layers.pattern_matching,
            ml_classification: case.layers.ml_classification,
            context_analysis: case.layers.context_analysis,
        },
        analysis_time_us: case.analysis_time_us,
    }
}

fn summarize_pairs(cases: &[CaseResult]) -> PairSummary {
    let mut pairs: BTreeMap<&str, Vec<&CaseResult>> = BTreeMap::new();
    for case in cases {
        pairs.entry(case.pair_id.as_str()).or_default().push(case);
    }
    let mut correct = 0;
    let mut failed = Vec::new();
    for (pair_id, pair_cases) in &pairs {
        let risky_ok = pair_cases
            .iter()
            .find(|case| case.cohort == "risky")
            .is_some_and(|case| case.expected_detected && case.exact_family);
        let safe_ok = pair_cases
            .iter()
            .find(|case| case.cohort == "safe")
            .is_some_and(|case| !case.any_alert);
        if risky_ok && safe_ok {
            correct += 1;
        } else {
            failed.push((*pair_id).to_string());
        }
    }
    PairSummary {
        total_pairs: pairs.len(),
        correct_pairs: correct,
        pair_accuracy: proportion(correct, pairs.len()),
        failed_pair_ids: failed,
    }
}

fn build_confusion_matrix(cases: &[CaseResult]) -> BTreeMap<String, BTreeMap<String, usize>> {
    let mut matrix: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    for case in cases {
        let expected = expected_label(case.expected_threat);
        let predicted = expected_label(case.operating_prediction);
        *matrix
            .entry(expected)
            .or_default()
            .entry(predicted)
            .or_default() += 1;
    }
    matrix
}

fn aggregate_diagnostics(
    cases: &[CaseResult],
) -> (BTreeMap<String, usize>, BTreeMap<String, usize>) {
    let mut layers = BTreeMap::new();
    let mut reasons = BTreeMap::new();
    for case in cases {
        *layers.entry("pattern_matching".to_string()).or_default() += case.layers.pattern_matching;
        *layers.entry("ml_classification".to_string()).or_default() +=
            case.layers.ml_classification;
        *layers.entry("context_analysis".to_string()).or_default() += case.layers.context_analysis;
        for code in &case.reason_codes {
            *reasons.entry(code.clone()).or_default() += 1;
        }
    }
    (layers, reasons)
}

fn summarize_metamorphic(
    seeds: &[MetamorphicSeed],
    cases: &[MetamorphicResult],
) -> MetamorphicSummary {
    let bases: BTreeMap<&str, bool> = cases
        .iter()
        .filter(|case| case.transform == "base")
        .map(|case| (case.seed_id.as_str(), case.detected))
        .collect();
    let variants: Vec<_> = cases
        .iter()
        .filter(|case| case.transform != "base")
        .collect();
    let seed_detected = bases.values().filter(|detected| **detected).count();
    let variant_detected = variants.iter().filter(|case| case.detected).count();
    let variants_from_detected_seeds: Vec<_> = variants
        .iter()
        .filter(|case| bases.get(case.seed_id.as_str()).copied().unwrap_or(false))
        .collect();
    let preserved = variants_from_detected_seeds
        .iter()
        .filter(|case| case.detected)
        .count();

    let transforms: BTreeSet<_> = variants
        .iter()
        .map(|case| case.transform.as_str())
        .collect();
    let by_transform = transforms
        .into_iter()
        .map(|transform| {
            let selected: Vec<_> = variants
                .iter()
                .filter(|case| case.transform == transform)
                .collect();
            let passed = selected.iter().filter(|case| case.detected).count();
            MetamorphicTransformSummary {
                transform: transform.to_string(),
                detected: proportion(passed, selected.len()),
                failed_case_ids: selected
                    .iter()
                    .filter(|case| !case.detected)
                    .map(|case| format!("{}::{transform}", case.seed_id))
                    .collect(),
            }
        })
        .collect();

    MetamorphicSummary {
        seed_detection: proportion(seed_detected, seeds.len()),
        variant_detection: proportion(variant_detected, variants.len()),
        decision_preservation_from_detected_seeds: proportion(
            preserved,
            variants_from_detected_seeds.len(),
        ),
        by_transform,
        failed_seed_ids: bases
            .iter()
            .filter(|(_, detected)| !**detected)
            .map(|(seed_id, _)| (*seed_id).to_string())
            .collect(),
        failed_variant_ids: variants
            .iter()
            .filter(|case| !case.detected)
            .map(|case| format!("{}::{}", case.seed_id, case.transform))
            .collect(),
    }
}

fn layer_counts(signals: &[aura_core::DetectionSignal]) -> LayerCounts {
    let mut counts = LayerCounts {
        pattern_matching: 0,
        ml_classification: 0,
        context_analysis: 0,
    };
    for signal in signals {
        match signal.layer {
            DetectionLayer::PatternMatching => counts.pattern_matching += 1,
            DetectionLayer::MlClassification => counts.ml_classification += 1,
            DetectionLayer::ContextAnalysis => counts.context_analysis += 1,
        }
    }
    counts
}

fn latency_summary(mut values: Vec<u64>) -> LatencySummary {
    values.sort_unstable();
    let count = values.len();
    let percentile = |fraction: f64| -> u64 {
        if values.is_empty() {
            return 0;
        }
        let index = ((values.len() - 1) as f64 * fraction).ceil() as usize;
        values[index]
    };
    LatencySummary {
        count,
        median_us: percentile(0.50),
        p95_us: percentile(0.95),
        max_us: values.last().copied().unwrap_or_default(),
    }
}

fn case_failed(case: &CaseResult) -> bool {
    match case.expected_threat {
        Some(_) => !case.expected_detected || !case.exact_family || case.action_error,
        None => case.any_alert || case.action_error,
    }
}

fn proportion(numerator: usize, denominator: usize) -> Proportion {
    if denominator == 0 {
        return Proportion {
            numerator,
            denominator,
            value: 0.0,
            wilson_95_low: 0.0,
            wilson_95_high: 1.0,
        };
    }
    let n = denominator as f64;
    let p = numerator as f64 / n;
    let z = 1.959_963_984_540_054_f64;
    let z2 = z * z;
    let denominator_term = 1.0 + z2 / n;
    let center = (p + z2 / (2.0 * n)) / denominator_term;
    let half = z * ((p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt()) / denominator_term;
    Proportion {
        numerator,
        denominator,
        value: p,
        wilson_95_low: (center - half).max(0.0),
        wilson_95_high: (center + half).min(1.0),
    }
}

fn expected_label(threat: Option<ThreatType>) -> String {
    threat
        .map(threat_label)
        .unwrap_or_else(|| "none".to_string())
}

fn threat_label(threat: ThreatType) -> String {
    serde_json::to_value(threat)
        .expect("serializable threat")
        .as_str()
        .expect("threat serializes as string")
        .to_string()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
