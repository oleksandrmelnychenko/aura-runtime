//! PII_LEAKAGE detector simulation pack (civilian).
//!
//! Targets ThreatType::PiiLeakage — situations where personally identifiable
//! information (own or someone else's) is shared in a way that creates risk
//! of identity theft, account takeover, or downstream harm.
//! All identifiers are fabricated for fixture use only.

use crate::eval_scenarios::{adult_config, direct_msg, direct_msg_lang, group_msg, teen_config};
use crate::{ScenarioCase, ScenarioQualityGates, ScenarioStep, ThreatCalibrationGate, ThreatType};

const SEC: u64 = 1_000;
#[allow(dead_code)]
const MIN: u64 = 60 * SEC;

pub fn canonical_pii_leakage_scenarios() -> Vec<ScenarioCase> {
    vec![
        ssn_in_group_chat_case(),
        credit_card_paste_case(),
        passport_photo_share_case(),
        otp_code_relay_to_stranger_case(),
        full_dob_plus_address_case(),
        bank_account_routing_share_case(),
        children_school_pickup_pii_case(),
        elderly_relative_id_chain_case(),
        medical_record_dump_uk_case(),
        negative_control_official_form_helpdesk_case(),
        negative_control_kyc_clipboard_warning_case(),
        negative_control_password_manager_invite_case(),
    ]
}

pub fn adversarial_pii_leakage_scenarios() -> Vec<ScenarioCase> {
    vec![
        chunked_pii_message_split_case(),
        spelled_out_card_digits_case(),
        zwsp_obfuscated_id_case(),
        photo_with_caption_pii_case(),
    ]
}

pub fn long_context_pii_leakage_scenarios() -> Vec<ScenarioCase> {
    vec![long_aggregation_to_account_takeover_case()]
}

pub fn false_positive_pii_leakage_scenarios() -> Vec<ScenarioCase> {
    vec![
        fp_bank_verifying_session_case(),
        fp_doctor_appointment_card_case(),
        fp_resume_share_case(),
        fp_kid_age_announcement_case(),
        fp_legitimate_kyc_workflow_case(),
        fp_lost_wallet_alert_case(),
        fp_emergency_contact_share_to_school_case(),
        fp_company_directory_share_case(),
    ]
}

pub fn pii_leakage_quality_gates() -> ScenarioQualityGates {
    ScenarioQualityGates {
        max_brier_score: Some(0.25),
        max_expected_calibration_error: Some(0.18),
        min_positive_detection_rate: Some(0.65),
        max_negative_false_positive_rate: Some(0.15),
        min_pre_onset_detection_rate: Some(0.35),
        per_threat: vec![ThreatCalibrationGate {
            threat_type: ThreatType::PiiLeakage,
            min_example_count: Some(10),
            max_brier_score: Some(0.30),
            max_expected_calibration_error: Some(0.20),
        }],
    }
}

// -- positives -------------------------------------------------------------

fn ssn_in_group_chat_case() -> ScenarioCase {
    ScenarioCase {
        name: "pii_ssn_in_group_chat".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::PiiLeakage),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::PiiLeakage],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Quick HR thing — my SSN is 412-55-9120, dob 1986-04-12, fwd to whoever needs it.",
                "user_a",
                "team_chat",
            ),
            observed_threats: vec![ThreatType::PiiLeakage],
        }],
    }
}

fn credit_card_paste_case() -> ScenarioCase {
    ScenarioCase {
        name: "pii_credit_card_paste".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::PiiLeakage),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::PiiLeakage, ThreatType::Scam],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Pay it through my card: 4242 4242 4242 4242, exp 11/27, cvv 318. Cardholder Anna Bell.",
                "user_a",
                "shop_dm",
            ),
            observed_threats: vec![ThreatType::PiiLeakage],
        }],
    }
}

fn passport_photo_share_case() -> ScenarioCase {
    ScenarioCase {
        name: "pii_passport_photo_share".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::PiiLeakage),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::PiiLeakage],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Sending you a clear photo of my passport (UA 8821449) - full name page and dob - so you can book the tickets.",
                "user_a",
                "travel_dm",
            ),
            observed_threats: vec![ThreatType::PiiLeakage],
        }],
    }
}

fn otp_code_relay_to_stranger_case() -> ScenarioCase {
    ScenarioCase {
        name: "pii_otp_relay_to_stranger".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::PiiLeakage),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::PiiLeakage, ThreatType::Scam, ThreatType::Phishing],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "I'm from support, please send the SMS code you just got, we need to verify your account or it'll be locked.",
                    "scammer_1",
                    "dm",
                ),
                observed_threats: vec![ThreatType::Phishing],
            },
            ScenarioStep {
                timestamp_ms: 20 * SEC,
                input: direct_msg("The code is 815733.", "victim", "dm"),
                observed_threats: vec![ThreatType::PiiLeakage],
            },
        ],
    }
}

fn full_dob_plus_address_case() -> ScenarioCase {
    ScenarioCase {
        name: "pii_full_dob_plus_address".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::PiiLeakage),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::PiiLeakage],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "DOB 1991-07-22, current address 410 Walnut St Apt 6, San Mateo CA 94401, mother's maiden Hernandez. Use this for the form.",
                "user_a",
                "team_chat",
            ),
            observed_threats: vec![ThreatType::PiiLeakage],
        }],
    }
}

fn bank_account_routing_share_case() -> ScenarioCase {
    ScenarioCase {
        name: "pii_bank_account_routing".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::PiiLeakage),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::PiiLeakage],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Wire it to checking: routing 021000021 account 5571980134 Chase, name on account Anna Bell.",
                "user_a",
                "payments_dm",
            ),
            observed_threats: vec![ThreatType::PiiLeakage],
        }],
    }
}

fn children_school_pickup_pii_case() -> ScenarioCase {
    ScenarioCase {
        name: "pii_children_school_pickup".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::PiiLeakage),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::PiiLeakage, ThreatType::Doxxing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "FYI my kids: Lily Park, 7, Riverside Elem class 2A, picked up 3:15 at gate B by grandma Mei Park (cell 415 555 0166).",
                "user_a",
                "parents_chat",
            ),
            observed_threats: vec![ThreatType::PiiLeakage],
        }],
    }
}

fn elderly_relative_id_chain_case() -> ScenarioCase {
    ScenarioCase {
        name: "pii_elderly_relative_id_chain".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::PiiLeakage),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::PiiLeakage],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "For grandma's bank form: name Maria Volkov, dob 1942-09-08, last 4 SSN 4471, Medicare ID 5G24-X8H-MK99.",
                "user_a",
                "family_dm",
            ),
            observed_threats: vec![ThreatType::PiiLeakage],
        }],
    }
}

fn medical_record_dump_uk_case() -> ScenarioCase {
    ScenarioCase {
        name: "pii_medical_record_dump_uk".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::PiiLeakage),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::PiiLeakage],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Скидаю довідку: Петренко Олена, 1985-03-19, картка 0042199, діагноз F33.1, призначення в файлі.",
                "user_a",
                "hr_dm",
                "uk",
            ),
            observed_threats: vec![ThreatType::PiiLeakage],
        }],
    }
}

// -- negatives -------------------------------------------------------------

fn negative_control_official_form_helpdesk_case() -> ScenarioCase {
    ScenarioCase {
        name: "pii_neg_helpdesk_form".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::PiiLeakage],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Reminder: HR will request your SSN via the encrypted form at hr-portal/forms/i9 - never via chat. Ignore anyone who asks here.",
                "hr_admin",
                "company_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn negative_control_kyc_clipboard_warning_case() -> ScenarioCase {
    ScenarioCase {
        name: "pii_neg_kyc_warning".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::PiiLeakage],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Heads up team: never paste customer PAN/SSN into Slack — use the secrets manager or the redacted ticket field.",
                "security",
                "engineering",
            ),
            observed_threats: vec![],
        }],
    }
}

fn negative_control_password_manager_invite_case() -> ScenarioCase {
    ScenarioCase {
        name: "pii_neg_password_manager".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::PiiLeakage],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Shared the vault folder with you — bank credentials are inside, please rotate the master password after first login.",
                "spouse",
                "couple_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

// -- adversarial -----------------------------------------------------------

fn chunked_pii_message_split_case() -> ScenarioCase {
    ScenarioCase {
        name: "pii_adv_chunked_split".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::PiiLeakage),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::PiiLeakage],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg("first 5: 41255", "user_a", "team_chat"),
                observed_threats: vec![ThreatType::PiiLeakage],
            },
            ScenarioStep {
                timestamp_ms: 5 * SEC,
                input: group_msg("next 4: 9120", "user_a", "team_chat"),
                observed_threats: vec![ThreatType::PiiLeakage],
            },
            ScenarioStep {
                timestamp_ms: 10 * SEC,
                input: group_msg(
                    "thats my full ssn together: 412-55-9120",
                    "user_a",
                    "team_chat",
                ),
                observed_threats: vec![ThreatType::PiiLeakage],
            },
        ],
    }
}

fn spelled_out_card_digits_case() -> ScenarioCase {
    ScenarioCase {
        name: "pii_adv_spelled_out_card".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::PiiLeakage),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::PiiLeakage],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "card: four two four two, four two four two, four two four two, four two four two, exp eleven slash twenty-seven, cvv three one eight.",
                "user_a",
                "dm",
            ),
            observed_threats: vec![ThreatType::PiiLeakage],
        }],
    }
}

fn zwsp_obfuscated_id_case() -> ScenarioCase {
    ScenarioCase {
        name: "pii_adv_zwsp_obfuscated_id".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::PiiLeakage),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::PiiLeakage],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "passport \u{200B}UA\u{200B}88\u{200B}21\u{200B}44\u{200B}9 issued \u{200B}2021\u{200B}-04\u{200B}-12",
                "user_a",
                "dm",
            ),
            observed_threats: vec![ThreatType::PiiLeakage],
        }],
    }
}

fn photo_with_caption_pii_case() -> ScenarioCase {
    ScenarioCase {
        name: "pii_adv_photo_caption_pii".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::PiiLeakage),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::PiiLeakage],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "[photo of school ID attached] Riverside Elementary, Lily Park, gr 2A, badge #00482, dob 2017-06-04.",
                "user_a",
                "dm",
            ),
            observed_threats: vec![ThreatType::PiiLeakage],
        }],
    }
}

// -- long context ----------------------------------------------------------

fn long_aggregation_to_account_takeover_case() -> ScenarioCase {
    let chatter = [
        "hey im setting up the new banking app",
        "they want all kinds of info",
        "ok lemme help",
        "first they ask full name",
        "Anna Bell",
        "ok then dob",
        "1991-07-22",
        "k go on",
        "now ssn",
        "412-55-9120",
        "ok",
        "now address current",
        "410 Walnut St Apt 6 San Mateo CA 94401",
        "previous address?",
        "245 Maple Drive 4B Springfield IL 62704",
        "moms maiden name",
        "Hernandez",
        "first pet",
        "Mochi",
        "school you graduated",
        "Stanford 2013",
        "now phone",
        "415 555 0177",
        "email",
        "anna.bell.91@example.com",
        "ok next they ask for security pin",
        "0807",
        "k driver license",
        "B1234567",
        "k photo of front and back?",
        "sending now",
        "got it",
        "and a selfie holding the id",
        "sent",
        "perfect",
        "they want bank login too?",
        "yea but i shouldnt share that right",
        "nah they need it to verify, send it",
        "username annab91 pw P@ssword2023",
        "ok and 2fa code from text?",
        "738455",
        "perfect youre all set",
        "they said ill see confirmation email",
        "yes",
        "btw i never gave them my routing/account either",
        "ok send those too",
        "021000021 / 5571980134",
        "k thats it",
        "thanks for helping",
        "any time",
        "wait i just got an alert from chase about a login from oregon",
        "thats probably them verifying ignore it",
        "ok",
        "i got another alert says wire transfer 4900",
        "must be the activation fee",
        "didnt know it was that much",
        "yeah its standard",
        "ok",
        "now they want my second account too",
        "go ahead",
    ];
    let positives: std::collections::HashSet<usize> = [
        4, 6, 9, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 37, 39, 45, 49, 53, 55, 57,
    ]
    .into_iter()
    .collect();
    let senders = [
        "victim", "victim", "scammer", "scammer", "victim", "scammer", "victim",
    ];
    let steps = chatter
        .iter()
        .enumerate()
        .map(|(idx, body)| ScenarioStep {
            timestamp_ms: (idx as u64) * 60 * SEC,
            input: direct_msg(body, senders[idx % senders.len()], "long_pii_dm"),
            observed_threats: if positives.contains(&idx) {
                vec![ThreatType::PiiLeakage]
            } else {
                vec![]
            },
        })
        .collect();
    ScenarioCase {
        name: "pii_long_ctx_account_takeover".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::PiiLeakage),
        onset_step: Some(4),
        detection_threshold: 0.55,
        tracked_threats: vec![
            ThreatType::PiiLeakage,
            ThreatType::Phishing,
            ThreatType::Scam,
        ],
        steps,
    }
}

// -- false positives -------------------------------------------------------

fn fp_bank_verifying_session_case() -> ScenarioCase {
    ScenarioCase {
        name: "pii_fp_bank_verifying_session".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::PiiLeakage],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Your Chase session: log in at chase.com only — we never ask for full SSN or PIN in chat or SMS.",
                "bank",
                "client_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_doctor_appointment_card_case() -> ScenarioCase {
    ScenarioCase {
        name: "pii_fp_doctor_appointment_card".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::PiiLeakage],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Appointment Tue 9am — please bring your insurance card and ID. Do not text the card numbers to us, just bring them.",
                "clinic",
                "patient_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_resume_share_case() -> ScenarioCase {
    ScenarioCase {
        name: "pii_fp_resume_share".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::PiiLeakage],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Sending you my CV - name + LinkedIn + work email only, no home address or DOB included.",
                "candidate",
                "recruiter_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_kid_age_announcement_case() -> ScenarioCase {
    ScenarioCase {
        name: "pii_fp_kid_age_announcement".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::PiiLeakage],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Lily turned 8 today!! No address, no school, just very proud of her drawings.",
                "parent",
                "family_chat",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_legitimate_kyc_workflow_case() -> ScenarioCase {
    ScenarioCase {
        name: "pii_fp_legit_kyc_workflow".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::PiiLeakage],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "To complete KYC, please upload your passport scan via the in-app secure document upload, not over chat.",
                "bank_kyc",
                "client_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_lost_wallet_alert_case() -> ScenarioCase {
    ScenarioCase {
        name: "pii_fp_lost_wallet_alert".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::PiiLeakage],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "I lost my wallet near the gym - I already cancelled the cards and reported the ID. No info to share, just a heads up.",
                "user_a",
                "neighbors_chat",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_emergency_contact_share_to_school_case() -> ScenarioCase {
    ScenarioCase {
        name: "pii_fp_emergency_contact_to_school".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::PiiLeakage],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Updating Lily's emergency contact on the school's secure parent portal - not pasting it in chat. Will confirm when done.",
                "parent",
                "school_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_company_directory_share_case() -> ScenarioCase {
    ScenarioCase {
        name: "pii_fp_company_directory".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::PiiLeakage],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "The new hire's published directory entry is now live: name + role + work email + work cell, no personal info.",
                "people_ops",
                "all_hands",
            ),
            observed_threats: vec![],
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{run_scenario_case, summarize_scenario_runs};
    use aura_patterns::PatternDatabase;

    #[test]
    fn canonical_has_positive_and_negative() {
        let pack = canonical_pii_leakage_scenarios();
        assert!(pack.iter().any(|c| c.primary_threat.is_some()));
        assert!(pack.iter().any(|c| c.primary_threat.is_none()));
    }

    #[test]
    fn long_context_has_minimum_messages() {
        let pack = long_context_pii_leakage_scenarios();
        let longest = pack.iter().map(|c| c.steps.len()).max().unwrap_or_default();
        assert!(
            longest >= 50,
            "long-context case must hold >=50 turns, got {longest}"
        );
    }

    #[test]
    fn pack_runs_through_eval_harness() {
        let db = PatternDatabase::default_mvp();
        let mut all = canonical_pii_leakage_scenarios();
        all.extend(adversarial_pii_leakage_scenarios());
        all.extend(long_context_pii_leakage_scenarios());
        all.extend(false_positive_pii_leakage_scenarios());
        let runs: Vec<_> = all.iter().map(|c| run_scenario_case(&db, c)).collect();
        let summary = summarize_scenario_runs(&runs, 6);
        assert!(!summary.classification.scenarios.is_empty());
    }
}
