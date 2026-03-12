use std::collections::BTreeSet;

use aura_patterns::PatternDatabase;

use crate::{
    canonical_messenger_scenarios, canonical_multilingual_scenarios,
    evaluate_scenario_quality_gates, run_scenario_case, summarize_scenario_runs, ScenarioCase,
    ScenarioEvaluationSummary, ScenarioQualityGates, ThreatCalibrationGate, ThreatType,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RobustnessProfile {
    EnglishTeenShorthand,
    UkrainianTeenShorthand,
    RussianTeenShorthand,
}

impl RobustnessProfile {
    pub fn label(self) -> &'static str {
        match self {
            Self::EnglishTeenShorthand => "english_teen_shorthand",
            Self::UkrainianTeenShorthand => "ukrainian_teen_shorthand",
            Self::RussianTeenShorthand => "russian_teen_shorthand",
        }
    }

    pub fn language_code(self) -> &'static str {
        match self {
            Self::EnglishTeenShorthand => "en",
            Self::UkrainianTeenShorthand => "uk",
            Self::RussianTeenShorthand => "ru",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RobustnessVariant {
    pub profile: RobustnessProfile,
    pub base_case_name: String,
    pub variant_name: String,
    pub mutated_steps: usize,
    pub case: ScenarioCase,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RobustnessProfileSummary {
    pub profile: RobustnessProfile,
    pub variant_count: usize,
    pub mutated_steps: usize,
    pub evaluation: ScenarioEvaluationSummary,
}

#[derive(Debug, Clone)]
pub struct RobustnessSuiteSummary {
    pub evaluation: ScenarioEvaluationSummary,
    pub profiles: Vec<RobustnessProfileSummary>,
    pub variants: Vec<RobustnessVariant>,
}

pub fn default_robustness_profiles() -> Vec<RobustnessProfile> {
    vec![
        RobustnessProfile::EnglishTeenShorthand,
        RobustnessProfile::UkrainianTeenShorthand,
        RobustnessProfile::RussianTeenShorthand,
    ]
}

pub fn canonical_robustness_seed_scenarios() -> Vec<ScenarioCase> {
    let mut names = BTreeSet::new();
    canonical_messenger_scenarios()
        .into_iter()
        .chain(canonical_multilingual_scenarios())
        .filter(|case| names.insert(case.name.clone()))
        .collect()
}

pub fn pre_release_robustness_gates() -> ScenarioQualityGates {
    ScenarioQualityGates {
        max_brier_score: Some(0.28),
        max_expected_calibration_error: Some(0.30),
        min_positive_detection_rate: Some(0.75),
        max_negative_false_positive_rate: Some(0.10),
        min_pre_onset_detection_rate: Some(0.25),
        per_threat: vec![
            ThreatCalibrationGate {
                threat_type: ThreatType::Grooming,
                min_example_count: Some(16),
                max_brier_score: Some(0.24),
                max_expected_calibration_error: Some(0.26),
            },
            ThreatCalibrationGate {
                threat_type: ThreatType::Manipulation,
                min_example_count: Some(16),
                max_brier_score: Some(0.28),
                max_expected_calibration_error: Some(0.30),
            },
            ThreatCalibrationGate {
                threat_type: ThreatType::SelfHarm,
                min_example_count: Some(6),
                max_brier_score: Some(0.26),
                max_expected_calibration_error: Some(0.28),
            },
            ThreatCalibrationGate {
                threat_type: ThreatType::Bullying,
                min_example_count: Some(10),
                max_brier_score: Some(0.22),
                max_expected_calibration_error: Some(0.26),
            },
        ],
    }
}

pub fn pre_release_robustness_profile_gates(profile: RobustnessProfile) -> ScenarioQualityGates {
    let per_threat = match profile {
        RobustnessProfile::EnglishTeenShorthand => vec![
            ThreatCalibrationGate {
                threat_type: ThreatType::Grooming,
                min_example_count: Some(10),
                max_brier_score: Some(0.24),
                max_expected_calibration_error: Some(0.26),
            },
            ThreatCalibrationGate {
                threat_type: ThreatType::Manipulation,
                min_example_count: Some(12),
                max_brier_score: Some(0.28),
                max_expected_calibration_error: Some(0.30),
            },
            ThreatCalibrationGate {
                threat_type: ThreatType::SelfHarm,
                min_example_count: Some(6),
                max_brier_score: Some(0.26),
                max_expected_calibration_error: Some(0.28),
            },
            ThreatCalibrationGate {
                threat_type: ThreatType::Bullying,
                min_example_count: Some(6),
                max_brier_score: Some(0.22),
                max_expected_calibration_error: Some(0.26),
            },
        ],
        RobustnessProfile::UkrainianTeenShorthand | RobustnessProfile::RussianTeenShorthand => {
            vec![
                ThreatCalibrationGate {
                    threat_type: ThreatType::Grooming,
                    min_example_count: Some(4),
                    max_brier_score: Some(0.24),
                    max_expected_calibration_error: Some(0.26),
                },
                ThreatCalibrationGate {
                    threat_type: ThreatType::Manipulation,
                    min_example_count: Some(4),
                    max_brier_score: Some(0.28),
                    max_expected_calibration_error: Some(0.30),
                },
                ThreatCalibrationGate {
                    threat_type: ThreatType::SelfHarm,
                    min_example_count: Some(3),
                    max_brier_score: Some(0.26),
                    max_expected_calibration_error: Some(0.28),
                },
                ThreatCalibrationGate {
                    threat_type: ThreatType::Bullying,
                    min_example_count: Some(3),
                    max_brier_score: Some(0.22),
                    max_expected_calibration_error: Some(0.26),
                },
            ]
        }
    };

    ScenarioQualityGates {
        max_brier_score: Some(0.28),
        max_expected_calibration_error: Some(0.30),
        min_positive_detection_rate: Some(0.75),
        max_negative_false_positive_rate: Some(0.10),
        min_pre_onset_detection_rate: Some(0.25),
        per_threat,
    }
}

pub fn generate_robustness_variants(
    cases: &[ScenarioCase],
    profiles: &[RobustnessProfile],
) -> Vec<RobustnessVariant> {
    let mut variants = Vec::new();

    for case in cases {
        for profile in profiles {
            if let Some(variant) = mutate_case_for_profile(case, *profile) {
                variants.push(variant);
            }
        }
    }

    variants
}

pub fn run_robustness_suite(
    pattern_db: &PatternDatabase,
    cases: &[ScenarioCase],
    profiles: &[RobustnessProfile],
    bin_count: usize,
) -> RobustnessSuiteSummary {
    let variants = generate_robustness_variants(cases, profiles);
    let runs: Vec<_> = variants
        .iter()
        .map(|variant| run_scenario_case(pattern_db, &variant.case))
        .collect();

    let mut profile_summaries = Vec::new();
    for profile in profiles {
        let profile_runs: Vec<_> = variants
            .iter()
            .zip(runs.iter())
            .filter(|(variant, _)| variant.profile == *profile)
            .map(|(_, run)| run.clone())
            .collect();
        if profile_runs.is_empty() {
            continue;
        }

        profile_summaries.push(RobustnessProfileSummary {
            profile: *profile,
            variant_count: profile_runs.len(),
            mutated_steps: variants
                .iter()
                .filter(|variant| variant.profile == *profile)
                .map(|variant| variant.mutated_steps)
                .sum(),
            evaluation: summarize_scenario_runs(&profile_runs, bin_count),
        });
    }

    RobustnessSuiteSummary {
        evaluation: summarize_scenario_runs(&runs, bin_count),
        profiles: profile_summaries,
        variants,
    }
}

pub fn evaluate_robustness_suite(
    summary: &RobustnessSuiteSummary,
    gates: &ScenarioQualityGates,
) -> (
    crate::ScenarioGateReport,
    Vec<(RobustnessProfile, crate::ScenarioGateReport)>,
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
                    &pre_release_robustness_profile_gates(profile.profile),
                ),
            )
        })
        .collect();
    (overall, by_profile)
}

fn mutate_case_for_profile(
    case: &ScenarioCase,
    profile: RobustnessProfile,
) -> Option<RobustnessVariant> {
    let mut mutated_steps = 0usize;
    let mut mutated_case = case.clone();

    for step in &mut mutated_case.steps {
        let step_language = normalize_language_code(
            step.input
                .language
                .as_deref()
                .or(Some(case.config.language.as_str())),
        );
        if step_language != profile.language_code() {
            continue;
        }
        let Some(text) = step.input.text.as_ref() else {
            continue;
        };
        let mutated = mutate_text_for_profile(text, profile);
        if mutated != *text {
            step.input.text = Some(mutated);
            mutated_steps += 1;
        }
    }

    if mutated_steps == 0 {
        return None;
    }

    let variant_name = format!("{}_{}", case.name, profile.label());
    mutated_case.name = variant_name.clone();

    Some(RobustnessVariant {
        profile,
        base_case_name: case.name.clone(),
        variant_name,
        mutated_steps,
        case: mutated_case,
    })
}

fn mutate_text_for_profile(text: &str, profile: RobustnessProfile) -> String {
    let mut mutated = text.to_lowercase();
    mutated = strip_light_punctuation(&mutated);

    match profile {
        RobustnessProfile::EnglishTeenShorthand => {
            mutated = apply_replacements(
                mutated,
                &[
                    ("where do you live", "where u live"),
                    ("what school do you go to", "what school u go to"),
                    ("what's your real name", "whats ur real name"),
                    ("what is your real name", "whats ur real name"),
                    ("message me on instagram", "msg me on insta"),
                    ("dm me on instagram", "msg me on insta"),
                    ("move this to telegram", "text me on tg"),
                    ("send me a photo", "send me pics"),
                    ("send me photos", "send me pics"),
                    ("i have screenshots", "i got screenshots"),
                    ("i have screenshot", "i got screenshots"),
                ],
            );
            mutated = apply_replacements(
                mutated,
                &[
                    (" your ", " ur "),
                    (" you're ", " ur "),
                    (" you are ", " u r "),
                    (" you ", " u "),
                    (" please ", " pls "),
                ],
            );
        }
        RobustnessProfile::UkrainianTeenShorthand => {
            mutated = apply_replacements(
                mutated,
                &[
                    ("в якій школі навчаєшся", "в якій школі вчишся"),
                    ("в якій школі ти навчаєшся", "в якій школі вчишся"),
                    ("інстаграм", "інст"),
                    ("телеграм", "тг"),
                    ("скріншоти", "скріни"),
                    ("скріншот", "скрін"),
                    ("заблокуєш", "заблочиш"),
                ],
            );
        }
        RobustnessProfile::RussianTeenShorthand => {
            mutated = apply_replacements(
                mutated,
                &[
                    ("инстаграм", "инст"),
                    ("телеграм", "тг"),
                    ("скриншоты", "скрины"),
                    ("скриншот", "скрин"),
                    ("заблокируешь", "заблочишь"),
                ],
            );
        }
    }

    collapse_whitespace(&mutated)
}

fn apply_replacements(mut text: String, replacements: &[(&str, &str)]) -> String {
    for (from, to) in replacements {
        text = text.replace(from, to);
    }
    text
}

fn strip_light_punctuation(text: &str) -> String {
    text.chars()
        .map(|ch| match ch {
            '"' | ',' | ';' | '(' | ')' => ' ',
            _ => ch,
        })
        .collect()
}

fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        run_scenario_case, AccountType, AuraConfig, ContentType, ConversationType, MessageInput,
        ProtectionLevel, ScenarioStep,
    };

    fn english_case() -> ScenarioCase {
        ScenarioCase {
            name: "english_case".to_string(),
            config: AuraConfig {
                account_type: AccountType::Child,
                protection_level: ProtectionLevel::High,
                language: "en".to_string(),
                ..AuraConfig::default()
            },
            primary_threat: Some(ThreatType::Grooming),
            onset_step: Some(0),
            detection_threshold: 0.5,
            tracked_threats: vec![ThreatType::Grooming],
            steps: vec![ScenarioStep {
                timestamp_ms: 1_000,
                input: MessageInput {
                    content_type: ContentType::Text,
                    text: Some("Where do you live? What school do you go to?".to_string()),
                    image_data: None,
                    sender_id: "stranger".to_string(),
                    conversation_id: "dm".to_string(),
                    language: Some("en".to_string()),
                    conversation_type: ConversationType::Direct,
                    member_count: None,
                },
                observed_threats: vec![ThreatType::Grooming],
            }],
        }
    }

    #[test]
    fn english_profile_mutates_matching_text() {
        let variant =
            mutate_case_for_profile(&english_case(), RobustnessProfile::EnglishTeenShorthand)
                .expect("english variant");

        assert_eq!(variant.mutated_steps, 1);
        let text = variant.case.steps[0].input.text.as_deref().expect("text");
        assert!(text.contains("where u live"));
        assert!(text.contains("school u go to"));
    }

    #[test]
    fn unsupported_language_is_skipped() {
        let variants = generate_robustness_variants(
            &[english_case()],
            &[RobustnessProfile::RussianTeenShorthand],
        );
        assert!(variants.is_empty());
    }

    #[test]
    fn robustness_suite_builds_profile_summaries() {
        let db = PatternDatabase::default_mvp();
        let summary = run_robustness_suite(
            &db,
            &[english_case()],
            &[RobustnessProfile::EnglishTeenShorthand],
            5,
        );

        assert_eq!(summary.variants.len(), 1);
        assert_eq!(summary.profiles.len(), 1);
        assert_eq!(
            summary.profiles[0].profile,
            RobustnessProfile::EnglishTeenShorthand
        );
        assert_eq!(summary.profiles[0].variant_count, 1);
        assert_eq!(
            summary.evaluation.classification.total_positive_scenarios,
            1
        );
    }

    #[test]
    fn mutated_english_case_remains_detectable() {
        let db = PatternDatabase::default_mvp();
        let variant =
            mutate_case_for_profile(&english_case(), RobustnessProfile::EnglishTeenShorthand)
                .expect("english variant");

        let run = run_scenario_case(&db, &variant.case);
        assert!(run.step_results[0]
            .detected_threats
            .iter()
            .any(|(threat, _)| *threat == ThreatType::Grooming));
    }
}
