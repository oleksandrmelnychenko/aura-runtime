use std::collections::BTreeSet;
use std::sync::OnceLock;

use aura_patterns::PatternDatabase;
use serde::Deserialize;

use crate::{
    canonical_policy_action_expectations, canonical_robustness_seed_scenarios,
    evaluate_policy_action_gates, evaluate_scenario_quality_gates, generate_robustness_variants,
    pre_release_policy_action_gates, pre_release_robustness_profile_gates, run_scenario_case,
    summarize_policy_actions_with_expectation_names, summarize_scenario_runs, AccountType,
    AuraConfig, ContentType, ConversationType, MessageInput, PolicyActionQualityGates,
    PolicyActionSummary, ProtectionLevel, RobustnessProfile, ScenarioCase,
    ScenarioEvaluationSummary, ScenarioGateReport, ScenarioQualityGates, ScenarioStep, ThreatType,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CorpusStyleProfile {
    EnglishCasualTeen,
    EnglishHighNoiseTeen,
    UkrainianCasualTeen,
    RussianCasualTeen,
}

impl CorpusStyleProfile {
    fn all() -> [Self; 4] {
        [
            Self::EnglishCasualTeen,
            Self::EnglishHighNoiseTeen,
            Self::UkrainianCasualTeen,
            Self::RussianCasualTeen,
        ]
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::EnglishCasualTeen => "english_casual_teen",
            Self::EnglishHighNoiseTeen => "english_high_noise_teen",
            Self::UkrainianCasualTeen => "ukrainian_casual_teen",
            Self::RussianCasualTeen => "russian_casual_teen",
        }
    }

    pub fn base_profile(self) -> RobustnessProfile {
        match self {
            Self::EnglishCasualTeen | Self::EnglishHighNoiseTeen => {
                RobustnessProfile::EnglishTeenShorthand
            }
            Self::UkrainianCasualTeen => RobustnessProfile::UkrainianTeenShorthand,
            Self::RussianCasualTeen => RobustnessProfile::RussianTeenShorthand,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CorpusStyleVariant {
    pub profile: CorpusStyleProfile,
    pub base_case_name: String,
    pub base_variant_name: String,
    pub variant_name: String,
    pub mutated_steps: usize,
    pub case: ScenarioCase,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CorpusStyleProfileSummary {
    pub profile: CorpusStyleProfile,
    pub variant_count: usize,
    pub mutated_steps: usize,
    pub evaluation: ScenarioEvaluationSummary,
    pub policy: PolicyActionSummary,
}

#[derive(Debug, Clone)]
pub struct CorpusStyleSuiteSummary {
    pub evaluation: ScenarioEvaluationSummary,
    pub policy: PolicyActionSummary,
    pub profiles: Vec<CorpusStyleProfileSummary>,
    pub variants: Vec<CorpusStyleVariant>,
}

#[derive(Debug, Clone, Deserialize)]
struct CorpusStyleBankFile {
    profiles: Vec<CorpusStyleBank>,
}

#[derive(Debug, Clone, Deserialize)]
struct CorpusStyleBank {
    id: String,
    #[serde(default)]
    general_replacements: Vec<TextReplacement>,
    #[serde(default)]
    targeted_replacements: Vec<TextReplacement>,
    filler: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct TextReplacement {
    from: String,
    to: String,
}

#[derive(Debug, Clone, Deserialize)]
struct CuratedCorpusFile {
    cases: Vec<CuratedCorpusCase>,
}

#[derive(Debug, Clone, Deserialize)]
struct CuratedCorpusCase {
    id: String,
    language: String,
    #[serde(default)]
    conversation_type: ConversationType,
    #[serde(default = "default_curated_detection_threshold")]
    detection_threshold: f32,
    #[serde(default)]
    primary_threat: Option<ThreatType>,
    #[serde(default)]
    onset_step: Option<usize>,
    #[serde(default)]
    tracked_threats: Vec<ThreatType>,
    #[serde(default = "default_curated_step_interval_ms")]
    step_interval_ms: u64,
    #[serde(default = "default_curated_account_type")]
    account_type: AccountType,
    #[serde(default = "default_curated_protection_level")]
    protection_level: ProtectionLevel,
    messages: Vec<CuratedCorpusMessage>,
}

#[derive(Debug, Clone, Deserialize)]
struct CuratedCorpusMessage {
    text: String,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    observed_threats: Vec<ThreatType>,
}

pub fn default_corpus_style_profiles() -> Vec<CorpusStyleProfile> {
    vec![
        CorpusStyleProfile::EnglishCasualTeen,
        CorpusStyleProfile::EnglishHighNoiseTeen,
        CorpusStyleProfile::UkrainianCasualTeen,
        CorpusStyleProfile::RussianCasualTeen,
    ]
}

pub fn canonical_corpus_seed_scenarios() -> Vec<ScenarioCase> {
    let mut names = BTreeSet::new();
    canonical_robustness_seed_scenarios()
        .into_iter()
        .chain(curated_corpus_scenarios())
        .filter(|case| names.insert(case.name.clone()))
        .collect()
}

pub fn pre_release_corpus_style_gates() -> ScenarioQualityGates {
    ScenarioQualityGates {
        max_brier_score: Some(0.28),
        max_expected_calibration_error: Some(0.30),
        min_positive_detection_rate: Some(0.75),
        max_negative_false_positive_rate: Some(0.10),
        min_pre_onset_detection_rate: Some(0.25),
        per_threat: pre_release_robustness_profile_gates(RobustnessProfile::EnglishTeenShorthand)
            .per_threat,
    }
}

pub fn pre_release_corpus_profile_gates(profile: CorpusStyleProfile) -> ScenarioQualityGates {
    let mut gates = pre_release_robustness_profile_gates(profile.base_profile());
    if profile == CorpusStyleProfile::EnglishHighNoiseTeen {
        gates.min_positive_detection_rate = Some(0.70);
        gates.max_brier_score = Some(0.30);
        gates.max_expected_calibration_error = Some(0.32);
    }
    gates
}

pub fn generate_corpus_style_variants(
    cases: &[ScenarioCase],
    profiles: &[CorpusStyleProfile],
) -> Vec<CorpusStyleVariant> {
    let mut variants = Vec::new();

    for profile in profiles {
        let robustness_variants = generate_robustness_variants(cases, &[profile.base_profile()]);
        for robustness_variant in robustness_variants {
            if let Some(variant) =
                mutate_robustness_variant_for_style(&robustness_variant, *profile)
            {
                variants.push(variant);
            }
        }
    }

    variants
}

pub fn run_corpus_style_suite(
    pattern_db: &PatternDatabase,
    cases: &[ScenarioCase],
    profiles: &[CorpusStyleProfile],
    bin_count: usize,
) -> CorpusStyleSuiteSummary {
    let variants = generate_corpus_style_variants(cases, profiles);
    let runs: Vec<_> = variants
        .iter()
        .map(|variant| run_scenario_case(pattern_db, &variant.case))
        .collect();
    let expectations = canonical_policy_action_expectations();
    let expected_policy_cases = expectations
        .iter()
        .map(|expectation| expectation.scenario_name.as_str())
        .collect::<BTreeSet<_>>();

    let profiles = profiles
        .iter()
        .filter_map(|profile| {
            let matching_pairs: Vec<_> = variants
                .iter()
                .zip(runs.iter())
                .filter(|(variant, _)| variant.profile == *profile)
                .collect();
            let profile_runs: Vec<_> = matching_pairs
                .iter()
                .map(|(_, run)| (*run).clone())
                .collect();
            if profile_runs.is_empty() {
                return None;
            }
            let policy_pairs = matching_pairs
                .iter()
                .filter(|(variant, _)| {
                    expected_policy_cases.contains(variant.base_case_name.as_str())
                })
                .collect::<Vec<_>>();
            let policy_runs = policy_pairs
                .iter()
                .map(|(_, run)| (*run).clone())
                .collect::<Vec<_>>();
            let expectation_names = policy_pairs
                .iter()
                .map(|(variant, _)| variant.base_case_name.clone())
                .collect::<Vec<_>>();

            Some(CorpusStyleProfileSummary {
                profile: *profile,
                variant_count: profile_runs.len(),
                mutated_steps: variants
                    .iter()
                    .filter(|variant| variant.profile == *profile)
                    .map(|variant| variant.mutated_steps)
                    .sum(),
                evaluation: summarize_scenario_runs(&profile_runs, bin_count),
                policy: summarize_policy_actions_with_expectation_names(
                    &policy_runs,
                    &expectation_names,
                    &expectations,
                ),
            })
        })
        .collect();
    let overall_policy_pairs = variants
        .iter()
        .zip(runs.iter())
        .filter(|(variant, _)| expected_policy_cases.contains(variant.base_case_name.as_str()))
        .collect::<Vec<_>>();
    let overall_policy_runs = overall_policy_pairs
        .iter()
        .map(|(_, run)| (*run).clone())
        .collect::<Vec<_>>();
    let overall_expectation_names = overall_policy_pairs
        .iter()
        .map(|(variant, _)| variant.base_case_name.clone())
        .collect::<Vec<_>>();

    CorpusStyleSuiteSummary {
        evaluation: summarize_scenario_runs(&runs, bin_count),
        policy: summarize_policy_actions_with_expectation_names(
            &overall_policy_runs,
            &overall_expectation_names,
            &expectations,
        ),
        profiles,
        variants,
    }
}

pub fn evaluate_corpus_style_suite(
    summary: &CorpusStyleSuiteSummary,
    gates: &ScenarioQualityGates,
) -> (
    ScenarioGateReport,
    Vec<(CorpusStyleProfile, ScenarioGateReport)>,
) {
    let overall = evaluate_scenario_quality_gates(&summary.evaluation, gates);
    let by_profile = summary
        .profiles
        .iter()
        .map(|profile| {
            (
                profile.profile,
                evaluate_scenario_quality_gates(
                    &profile.evaluation,
                    &pre_release_corpus_profile_gates(profile.profile),
                ),
            )
        })
        .collect();

    (overall, by_profile)
}

pub fn evaluate_corpus_style_policy_suite(
    summary: &CorpusStyleSuiteSummary,
    gates: &PolicyActionQualityGates,
) -> (
    ScenarioGateReport,
    Vec<(CorpusStyleProfile, ScenarioGateReport)>,
) {
    let overall = evaluate_policy_action_gates(&summary.policy, gates);
    let by_profile = summary
        .profiles
        .iter()
        .filter(|profile| profile.policy.total_scenarios > 0)
        .map(|profile| {
            (
                profile.profile,
                evaluate_policy_action_gates(&profile.policy, gates),
            )
        })
        .collect();

    (overall, by_profile)
}

pub fn pre_release_corpus_policy_gates() -> PolicyActionQualityGates {
    pre_release_policy_action_gates()
}

fn mutate_robustness_variant_for_style(
    robustness_variant: &crate::RobustnessVariant,
    profile: CorpusStyleProfile,
) -> Option<CorpusStyleVariant> {
    let mut mutated_case = robustness_variant.case.clone();
    let mut mutated_steps = 0usize;
    let language_code = profile.base_profile().language_code();

    for step in &mut mutated_case.steps {
        let step_language = normalize_language_code(
            step.input
                .language
                .as_deref()
                .or(Some(mutated_case.config.language.as_str())),
        );
        if step_language != language_code {
            continue;
        }

        let Some(text) = step.input.text.as_ref() else {
            continue;
        };
        let mutated = mutate_text_for_style(text, profile);
        if mutated != *text {
            step.input.text = Some(mutated);
            mutated_steps += 1;
        }
    }

    if mutated_steps == 0 {
        return None;
    }

    let variant_name = format!("{}_{}", robustness_variant.variant_name, profile.label());
    mutated_case.name = variant_name.clone();

    Some(CorpusStyleVariant {
        profile,
        base_case_name: robustness_variant.base_case_name.clone(),
        base_variant_name: robustness_variant.variant_name.clone(),
        variant_name,
        mutated_steps,
        case: mutated_case,
    })
}

fn mutate_text_for_style(text: &str, profile: CorpusStyleProfile) -> String {
    let mut mutated = text.to_string();
    let bank = corpus_style_bank(profile);

    mutated = apply_replacements(mutated, &bank.general_replacements);
    mutated = apply_replacements(mutated, &bank.targeted_replacements);

    if let Some(filler) = bank
        .filler
        .as_deref()
        .map(str::trim)
        .filter(|filler| !filler.is_empty())
    {
        mutated = append_filler(&mutated, filler);
    }

    collapse_whitespace(&mutated)
}

fn curated_corpus_scenarios() -> Vec<ScenarioCase> {
    curated_corpus_file()
        .cases
        .iter()
        .map(build_curated_scenario_case)
        .collect()
}

fn apply_replacements(mut text: String, replacements: &[TextReplacement]) -> String {
    for replacement in replacements {
        text = text.replace(&replacement.from, &replacement.to);
    }
    text
}

fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn append_filler(text: &str, filler: &str) -> String {
    if text
        .split_whitespace()
        .last()
        .is_some_and(|token| token == filler)
    {
        text.to_string()
    } else {
        format!("{text} {filler}")
    }
}

fn normalize_language_code(language: Option<&str>) -> String {
    language
        .map(str::trim)
        .filter(|language| !language.is_empty())
        .map(|language| {
            language
                .split('-')
                .next()
                .unwrap_or(language)
                .to_ascii_lowercase()
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn curated_corpus_file() -> &'static CuratedCorpusFile {
    static CURATED_FILE: OnceLock<CuratedCorpusFile> = OnceLock::new();
    CURATED_FILE.get_or_init(|| {
        let file = serde_json::from_str::<CuratedCorpusFile>(include_str!(
            "../data/corpus_curated_cases.json"
        ))
        .expect("valid curated corpus json");
        validate_curated_corpus_file(&file).expect("valid curated corpus cases");
        file
    })
}

fn corpus_style_bank(profile: CorpusStyleProfile) -> &'static CorpusStyleBank {
    corpus_style_bank_file()
        .profiles
        .iter()
        .find(|bank| bank.id == profile.label())
        .unwrap_or_else(|| panic!("missing corpus style bank for {}", profile.label()))
}

fn corpus_style_bank_file() -> &'static CorpusStyleBankFile {
    static BANK_FILE: OnceLock<CorpusStyleBankFile> = OnceLock::new();
    BANK_FILE.get_or_init(|| {
        let file = serde_json::from_str::<CorpusStyleBankFile>(include_str!(
            "../data/corpus_style_profiles.json"
        ))
        .expect("valid corpus style profile json");
        validate_corpus_style_bank_file(&file).expect("valid corpus style profile bank");
        file
    })
}

fn validate_corpus_style_bank_file(file: &CorpusStyleBankFile) -> Result<(), String> {
    let mut ids = std::collections::BTreeSet::new();

    for bank in &file.profiles {
        if bank.id.trim().is_empty() {
            return Err("corpus style bank id must not be empty".to_string());
        }
        if !ids.insert(bank.id.clone()) {
            return Err(format!("duplicate corpus style bank id: {}", bank.id));
        }

        validate_replacements(&bank.id, "general_replacements", &bank.general_replacements)?;
        validate_replacements(
            &bank.id,
            "targeted_replacements",
            &bank.targeted_replacements,
        )?;

        if bank
            .filler
            .as_deref()
            .is_some_and(|filler| filler.trim().is_empty())
        {
            return Err(format!("corpus style bank filler is empty for {}", bank.id));
        }
    }

    for profile in CorpusStyleProfile::all() {
        if !ids.contains(profile.label()) {
            return Err(format!(
                "missing corpus style bank entry for profile {}",
                profile.label()
            ));
        }
    }

    for id in ids {
        if !CorpusStyleProfile::all()
            .iter()
            .any(|profile| profile.label() == id)
        {
            return Err(format!("unknown corpus style bank id: {id}"));
        }
    }

    Ok(())
}

fn validate_replacements(
    bank_id: &str,
    field_name: &str,
    replacements: &[TextReplacement],
) -> Result<(), String> {
    for replacement in replacements {
        if replacement.from.trim().is_empty() {
            return Err(format!(
                "{bank_id}.{field_name} contains empty `from` replacement"
            ));
        }
        if replacement.to.trim().is_empty() {
            return Err(format!(
                "{bank_id}.{field_name} contains empty `to` replacement"
            ));
        }
    }

    Ok(())
}

fn validate_curated_corpus_file(file: &CuratedCorpusFile) -> Result<(), String> {
    let mut ids = BTreeSet::new();

    for case in &file.cases {
        if case.id.trim().is_empty() {
            return Err("curated corpus case id must not be empty".to_string());
        }
        if !ids.insert(case.id.clone()) {
            return Err(format!("duplicate curated corpus case id: {}", case.id));
        }
        if case.language.trim().is_empty() {
            return Err(format!(
                "curated corpus case {} has empty language",
                case.id
            ));
        }
        if !(0.0..=1.0).contains(&case.detection_threshold) {
            return Err(format!(
                "curated corpus case {} has invalid detection_threshold {}",
                case.id, case.detection_threshold
            ));
        }
        if case.step_interval_ms == 0 {
            return Err(format!(
                "curated corpus case {} has zero step_interval_ms",
                case.id
            ));
        }
        if case.messages.is_empty() {
            return Err(format!("curated corpus case {} has no messages", case.id));
        }
        if let Some(onset_step) = case.onset_step {
            if onset_step >= case.messages.len() {
                return Err(format!(
                    "curated corpus case {} onset_step {} is out of bounds",
                    case.id, onset_step
                ));
            }
        }
        for message in &case.messages {
            if message.text.trim().is_empty() {
                return Err(format!(
                    "curated corpus case {} contains empty message text",
                    case.id
                ));
            }
        }
    }

    Ok(())
}

fn build_curated_scenario_case(case: &CuratedCorpusCase) -> ScenarioCase {
    let config = AuraConfig {
        account_type: case.account_type,
        protection_level: case.protection_level,
        language: case.language.clone(),
        ..AuraConfig::default()
    };

    let tracked_threats = if case.tracked_threats.is_empty() {
        case.primary_threat.into_iter().collect()
    } else {
        case.tracked_threats.clone()
    };

    let steps = case
        .messages
        .iter()
        .enumerate()
        .map(|(idx, message)| ScenarioStep {
            timestamp_ms: idx as u64 * case.step_interval_ms,
            input: MessageInput {
                content_type: ContentType::Text,
                text: Some(message.text.clone()),
                image_data: None,
                sender_id: message
                    .sender_id
                    .clone()
                    .unwrap_or_else(|| format!("sender_{idx}")),
                conversation_id: case.id.clone(),
                language: Some(case.language.clone()),
                conversation_type: case.conversation_type,
                member_count: matches!(case.conversation_type, ConversationType::Direct)
                    .then_some(2)
                    .or(Some(6)),
            },
            observed_threats: message.observed_threats.clone(),
        })
        .collect();

    ScenarioCase {
        name: case.id.clone(),
        config,
        primary_threat: case.primary_threat,
        onset_step: case.onset_step,
        detection_threshold: case.detection_threshold,
        tracked_threats,
        steps,
    }
}

fn default_curated_detection_threshold() -> f32 {
    0.55
}

fn default_curated_step_interval_ms() -> u64 {
    60_000
}

fn default_curated_account_type() -> AccountType {
    AccountType::Child
}

fn default_curated_protection_level() -> ProtectionLevel {
    ProtectionLevel::High
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn english_high_noise_profile_injects_interstitial_noise() {
        let variants = generate_corpus_style_variants(
            &canonical_corpus_seed_scenarios(),
            &[CorpusStyleProfile::EnglishHighNoiseTeen],
        );
        let variant = variants
            .iter()
            .find(|variant| variant.base_case_name == "classic_grooming")
            .expect("english high-noise classic grooming");

        let joined = variant
            .case
            .steps
            .iter()
            .filter_map(|step| step.input.text.as_deref())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(joined.contains("w.h.e.r.e u liiive") || joined.contains("i.n.s.t.a"));
    }

    #[test]
    fn corpus_style_suite_builds_profile_summaries() {
        let db = PatternDatabase::default_mvp();
        let summary = run_corpus_style_suite(
            &db,
            &canonical_corpus_seed_scenarios(),
            &[CorpusStyleProfile::EnglishCasualTeen],
            5,
        );

        assert!(!summary.variants.is_empty());
        assert_eq!(summary.profiles.len(), 1);
        assert_eq!(
            summary.profiles[0].profile,
            CorpusStyleProfile::EnglishCasualTeen
        );
        assert!(summary.evaluation.classification.total_positive_scenarios > 0);
    }

    #[test]
    fn corpus_style_suite_preserves_negative_controls() {
        let db = PatternDatabase::default_mvp();
        let summary = run_corpus_style_suite(
            &db,
            &canonical_corpus_seed_scenarios(),
            &[CorpusStyleProfile::EnglishCasualTeen],
            5,
        );

        assert_eq!(
            summary
                .evaluation
                .classification
                .negative_false_positive_rate,
            0.0
        );
    }

    #[test]
    fn corpus_style_policy_suite_passes_for_supported_cases() {
        let db = PatternDatabase::default_mvp();
        let summary = run_corpus_style_suite(
            &db,
            &canonical_corpus_seed_scenarios(),
            &default_corpus_style_profiles(),
            5,
        );
        let (overall, profiles) =
            evaluate_corpus_style_policy_suite(&summary, &pre_release_corpus_policy_gates());

        assert!(
            overall.passed,
            "corpus-style policy gates failed: {overall:?}"
        );
        for (profile, report) in profiles {
            assert!(
                report.passed,
                "corpus-style policy gates failed for {}: {report:?}",
                profile.label()
            );
        }
    }

    #[test]
    fn corpus_style_policy_summary_filters_unmapped_curated_cases() {
        let db = PatternDatabase::default_mvp();
        let summary = run_corpus_style_suite(
            &db,
            &canonical_corpus_seed_scenarios(),
            &[CorpusStyleProfile::EnglishCasualTeen],
            5,
        );

        assert!(summary.policy.total_scenarios > 0);
        assert!(
            summary.policy.total_scenarios
                < summary.evaluation.classification.total_positive_scenarios
                    + summary.evaluation.classification.total_negative_scenarios
        );
    }

    #[test]
    fn corpus_style_policy_suite_covers_every_profile() {
        let db = PatternDatabase::default_mvp();
        let summary = run_corpus_style_suite(
            &db,
            &canonical_corpus_seed_scenarios(),
            &default_corpus_style_profiles(),
            5,
        );
        let (_, profiles) =
            evaluate_corpus_style_policy_suite(&summary, &pre_release_corpus_policy_gates());

        assert_eq!(profiles.len(), summary.profiles.len());
        for profile in &summary.profiles {
            assert!(
                profile.policy.total_scenarios > 0,
                "profile {} should have policy-covered scenarios",
                profile.profile.label()
            );
        }
    }

    #[test]
    fn corpus_style_bank_file_covers_all_profiles() {
        let bank_file = corpus_style_bank_file();
        assert_eq!(bank_file.profiles.len(), CorpusStyleProfile::all().len());
        for profile in CorpusStyleProfile::all() {
            let bank = corpus_style_bank(profile);
            assert_eq!(bank.id, profile.label());
        }
    }

    #[test]
    fn curated_corpus_file_loads_expected_cases() {
        let curated = curated_corpus_file();
        assert!(curated.cases.len() >= 8);
        assert!(curated
            .cases
            .iter()
            .any(|case| case.id == "curated_en_grooming_probe"));
        assert!(curated
            .cases
            .iter()
            .any(|case| case.id == "curated_negative_en_peer_support"));
    }

    #[test]
    fn canonical_corpus_seed_scenarios_include_curated_cases() {
        let seeds = canonical_corpus_seed_scenarios();
        assert!(seeds
            .iter()
            .any(|case| case.name == "curated_en_grooming_probe"));
        assert!(seeds
            .iter()
            .any(|case| case.name == "curated_negative_uk_school_logistics"));
    }
}
