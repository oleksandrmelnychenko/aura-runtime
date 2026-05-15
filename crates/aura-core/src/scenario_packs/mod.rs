//! Per-detector scenario simulation packs.
//!
//! Each submodule exposes four scenario builders and a `quality_gates()` helper.
//! Builders return `Vec<ScenarioCase>` so they slot into `run_scenario_case` /
//! `summarize_scenario_runs` exactly like the canonical packs in
//! `eval_scenarios.rs`.
//!
//! Contract per detector:
//! - `canonical_*_scenarios()` — multi-step positive + negative controls
//! - `adversarial_*_scenarios()` — obfuscation (leetspeak, code-switch, emoji)
//! - `long_context_*_scenarios()` — 50-200 message conversations
//! - `false_positive_*_scenarios()` — high-recall lookalikes that must NOT fire
//! - `*_quality_gates()` — Brier/ECE/detection/FPR thresholds for CI gates
//!
//! Packs are wired through `pack_index()` so harnesses (and CI) can iterate
//! over every detector without hard-coding names.

use crate::{ScenarioCase, ScenarioQualityGates, ThreatType};

pub mod coordinate_leak;
pub mod doxxing;
pub mod explicit_threat;
pub mod hate_speech;
pub mod military_social_eng;
pub mod nsfw;
pub mod opsec_violation;
pub mod phishing;
pub mod pii_leakage;
pub mod psyops;
pub mod spam_scam;
pub mod volume;

/// A bundle of scenarios + gates for a single detector.
pub struct DetectorPack {
    pub threat: ThreatType,
    pub name: &'static str,
    pub canonical: fn() -> Vec<ScenarioCase>,
    pub adversarial: fn() -> Vec<ScenarioCase>,
    pub long_context: fn() -> Vec<ScenarioCase>,
    pub false_positive: fn() -> Vec<ScenarioCase>,
    pub gates: fn() -> ScenarioQualityGates,
}

impl DetectorPack {
    pub fn all_scenarios(&self) -> Vec<ScenarioCase> {
        let mut out = (self.canonical)();
        out.extend((self.adversarial)());
        out.extend((self.long_context)());
        out.extend((self.false_positive)());
        out
    }
}

/// Returns every registered detector pack. Order is stable so CI reports are
/// reproducible.
pub fn pack_index() -> Vec<DetectorPack> {
    vec![
        DetectorPack {
            threat: ThreatType::HateSpeech,
            name: "hate_speech",
            canonical: hate_speech::canonical_hate_speech_scenarios,
            adversarial: hate_speech::adversarial_hate_speech_scenarios,
            long_context: hate_speech::long_context_hate_speech_scenarios,
            false_positive: hate_speech::false_positive_hate_speech_scenarios,
            gates: hate_speech::hate_speech_quality_gates,
        },
        DetectorPack {
            threat: ThreatType::Doxxing,
            name: "doxxing",
            canonical: doxxing::canonical_doxxing_scenarios,
            adversarial: doxxing::adversarial_doxxing_scenarios,
            long_context: doxxing::long_context_doxxing_scenarios,
            false_positive: doxxing::false_positive_doxxing_scenarios,
            gates: doxxing::doxxing_quality_gates,
        },
        DetectorPack {
            threat: ThreatType::Nsfw,
            name: "nsfw",
            canonical: nsfw::canonical_nsfw_scenarios,
            adversarial: nsfw::adversarial_nsfw_scenarios,
            long_context: nsfw::long_context_nsfw_scenarios,
            false_positive: nsfw::false_positive_nsfw_scenarios,
            gates: nsfw::nsfw_quality_gates,
        },
        DetectorPack {
            threat: ThreatType::PiiLeakage,
            name: "pii_leakage",
            canonical: pii_leakage::canonical_pii_leakage_scenarios,
            adversarial: pii_leakage::adversarial_pii_leakage_scenarios,
            long_context: pii_leakage::long_context_pii_leakage_scenarios,
            false_positive: pii_leakage::false_positive_pii_leakage_scenarios,
            gates: pii_leakage::pii_leakage_quality_gates,
        },
        DetectorPack {
            threat: ThreatType::Phishing,
            name: "phishing",
            canonical: phishing::canonical_phishing_scenarios,
            adversarial: phishing::adversarial_phishing_scenarios,
            long_context: phishing::long_context_phishing_scenarios,
            false_positive: phishing::false_positive_phishing_scenarios,
            gates: phishing::phishing_quality_gates,
        },
        DetectorPack {
            threat: ThreatType::Scam,
            name: "spam_scam",
            canonical: spam_scam::canonical_spam_scam_scenarios,
            adversarial: spam_scam::adversarial_spam_scam_scenarios,
            long_context: spam_scam::long_context_spam_scam_scenarios,
            false_positive: spam_scam::false_positive_spam_scam_scenarios,
            gates: spam_scam::spam_scam_quality_gates,
        },
        DetectorPack {
            threat: ThreatType::Threat,
            name: "explicit_threat",
            canonical: explicit_threat::canonical_explicit_threat_scenarios,
            adversarial: explicit_threat::adversarial_explicit_threat_scenarios,
            long_context: explicit_threat::long_context_explicit_threat_scenarios,
            false_positive: explicit_threat::false_positive_explicit_threat_scenarios,
            gates: explicit_threat::explicit_threat_quality_gates,
        },
        DetectorPack {
            threat: ThreatType::OpsecViolation,
            name: "opsec_violation",
            canonical: opsec_violation::canonical_opsec_violation_scenarios,
            adversarial: opsec_violation::adversarial_opsec_violation_scenarios,
            long_context: opsec_violation::long_context_opsec_violation_scenarios,
            false_positive: opsec_violation::false_positive_opsec_violation_scenarios,
            gates: opsec_violation::opsec_violation_quality_gates,
        },
        DetectorPack {
            threat: ThreatType::Psyops,
            name: "psyops",
            canonical: psyops::canonical_psyops_scenarios,
            adversarial: psyops::adversarial_psyops_scenarios,
            long_context: psyops::long_context_psyops_scenarios,
            false_positive: psyops::false_positive_psyops_scenarios,
            gates: psyops::psyops_quality_gates,
        },
        DetectorPack {
            threat: ThreatType::MilitarySocialEng,
            name: "military_social_eng",
            canonical: military_social_eng::canonical_military_social_eng_scenarios,
            adversarial: military_social_eng::adversarial_military_social_eng_scenarios,
            long_context: military_social_eng::long_context_military_social_eng_scenarios,
            false_positive: military_social_eng::false_positive_military_social_eng_scenarios,
            gates: military_social_eng::military_social_eng_quality_gates,
        },
        DetectorPack {
            threat: ThreatType::CoordinateLeak,
            name: "coordinate_leak",
            canonical: coordinate_leak::canonical_coordinate_leak_scenarios,
            adversarial: coordinate_leak::adversarial_coordinate_leak_scenarios,
            long_context: coordinate_leak::long_context_coordinate_leak_scenarios,
            false_positive: coordinate_leak::false_positive_coordinate_leak_scenarios,
            gates: coordinate_leak::coordinate_leak_quality_gates,
        },
    ]
}
