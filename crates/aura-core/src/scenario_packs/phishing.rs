//! PHISHING detector simulation pack.
//!
//! Targets ThreatType::Phishing — credential / account theft attempts via
//! deceptive links and pretexting. All URLs use `.example` placeholders.

use crate::eval_scenarios::{
    adult_config, direct_msg, direct_msg_lang, group_msg, group_msg_lang_size, teen_config,
};
use crate::{ScenarioCase, ScenarioQualityGates, ScenarioStep, ThreatCalibrationGate, ThreatType};

const SEC: u64 = 1_000;
#[allow(dead_code)]
const MIN: u64 = 60 * SEC;

pub fn canonical_phishing_scenarios() -> Vec<ScenarioCase> {
    vec![
        bank_fraud_alert_link_case(),
        crypto_wallet_recovery_case(),
        delivery_redelivery_fee_case(),
        irs_tax_refund_pretext_case(),
        microsoft_365_password_expiry_case(),
        invoice_pdf_credential_capture_case(),
        government_benefits_uk_case(),
        oauth_consent_abuse_case(),
        ceo_fraud_urgency_case(),
        teenage_steam_giveaway_case(),
        negative_control_official_password_reset_case(),
        negative_control_security_team_warning_case(),
        negative_control_email_phish_report_case(),
    ]
}

pub fn adversarial_phishing_scenarios() -> Vec<ScenarioCase> {
    vec![
        unicode_homograph_url_case(),
        url_shortened_to_punycode_case(),
        zwsp_inside_brand_name_case(),
        sms_pretext_with_otp_relay_case(),
    ]
}

pub fn long_context_phishing_scenarios() -> Vec<ScenarioCase> {
    vec![long_pretext_to_full_takeover_case()]
}

pub fn false_positive_phishing_scenarios() -> Vec<ScenarioCase> {
    vec![
        fp_real_password_reset_self_initiated_case(),
        fp_security_advisory_announcement_case(),
        fp_oauth_consent_legit_case(),
        fp_anti_phishing_training_case(),
        fp_news_about_phishing_campaign_case(),
        fp_courier_real_status_link_case(),
        fp_2fa_self_request_case(),
        fp_user_warning_others_case(),
    ]
}

pub fn phishing_quality_gates() -> ScenarioQualityGates {
    ScenarioQualityGates {
        max_brier_score: Some(0.25),
        max_expected_calibration_error: Some(0.18),
        min_positive_detection_rate: Some(0.70),
        max_negative_false_positive_rate: Some(0.15),
        min_pre_onset_detection_rate: Some(0.45),
        per_threat: vec![ThreatCalibrationGate {
            threat_type: ThreatType::Phishing,
            min_example_count: Some(10),
            max_brier_score: Some(0.30),
            max_expected_calibration_error: Some(0.20),
        }],
    }
}

// -- positives -------------------------------------------------------------

fn bank_fraud_alert_link_case() -> ScenarioCase {
    ScenarioCase {
        name: "phish_bank_fraud_alert_link".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Phishing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "URGENT: suspicious activity on your Chase account. Verify identity now or it will be frozen: https://chase-secure.example.com/verify?id=ax821",
                "scammer_1",
                "dm",
            ),
            observed_threats: vec![ThreatType::Phishing],
        }],
    }
}

fn crypto_wallet_recovery_case() -> ScenarioCase {
    ScenarioCase {
        name: "phish_crypto_wallet_recovery".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Phishing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing, ThreatType::Scam],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Hi from MetaMask support — we noticed your wallet syncing issue, paste your 12-word seed phrase here so we can restore it.",
                "scammer_2",
                "dm",
            ),
            observed_threats: vec![ThreatType::Phishing, ThreatType::Scam],
        }],
    }
}

fn delivery_redelivery_fee_case() -> ScenarioCase {
    ScenarioCase {
        name: "phish_delivery_redelivery_fee".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Phishing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "USPS: package #UA882144 held — pay $1.95 redelivery fee at https://usps-redelivery.example.co/track to release.",
                "scammer_3",
                "dm",
            ),
            observed_threats: vec![ThreatType::Phishing],
        }],
    }
}

fn irs_tax_refund_pretext_case() -> ScenarioCase {
    ScenarioCase {
        name: "phish_irs_tax_refund".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Phishing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "IRS Notice: refund of $2,140 pending. Confirm SSN and banking details at https://irs-refund.example.gov-claim.example/portal within 24h.",
                "scammer_4",
                "dm",
            ),
            observed_threats: vec![ThreatType::Phishing],
        }],
    }
}

fn microsoft_365_password_expiry_case() -> ScenarioCase {
    ScenarioCase {
        name: "phish_m365_password_expiry".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Phishing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Your Microsoft 365 password expires today. Keep current password: https://m365-keep-password.example.com/o365/signin",
                "scammer_5",
                "work_dm",
            ),
            observed_threats: vec![ThreatType::Phishing],
        }],
    }
}

fn invoice_pdf_credential_capture_case() -> ScenarioCase {
    ScenarioCase {
        name: "phish_invoice_pdf_credential_capture".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Phishing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Attached invoice #INV-4471 needs your approval — open at https://docpreview.example.com/login?ret=invoice_4471 (sign in with your work email).",
                "scammer_6",
                "work_dm",
            ),
            observed_threats: vec![ThreatType::Phishing],
        }],
    }
}

fn government_benefits_uk_case() -> ScenarioCase {
    ScenarioCase {
        name: "phish_government_benefits_uk".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Phishing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "Дія: ваша грошова виплата чекає підтвердження. Введіть номер картки за посиланням до 12:00 https://diia-vyplata.example.ua/login",
                "scammer_7",
                "dm",
                "uk",
            ),
            observed_threats: vec![ThreatType::Phishing],
        }],
    }
}

fn oauth_consent_abuse_case() -> ScenarioCase {
    ScenarioCase {
        name: "phish_oauth_consent_abuse".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Phishing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Calendar Add-on requested. Click 'Allow' on the Google prompt to grant access — it asks for full mail + contacts but that's normal.",
                "scammer_8",
                "work_dm",
            ),
            observed_threats: vec![ThreatType::Phishing],
        }],
    }
}

fn ceo_fraud_urgency_case() -> ScenarioCase {
    ScenarioCase {
        name: "phish_ceo_fraud_urgency".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Phishing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing, ThreatType::Scam],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "[CEO] In a board call — quick: I need a wire to 5571980134 / routing 021000021 ASAP, $48k, signal-back when sent.",
                    "fake_ceo",
                    "finance_dm",
                ),
                observed_threats: vec![ThreatType::Phishing, ThreatType::Scam],
            },
            ScenarioStep {
                timestamp_ms: 30 * SEC,
                input: direct_msg(
                    "Cant talk on phone right now. Just do it, settle the JV deposit, I'll explain after.",
                    "fake_ceo",
                    "finance_dm",
                ),
                observed_threats: vec![ThreatType::Phishing, ThreatType::Scam],
            },
        ],
    }
}

fn teenage_steam_giveaway_case() -> ScenarioCase {
    ScenarioCase {
        name: "phish_teen_steam_giveaway".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::Phishing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing, ThreatType::Scam],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "FREE STEAM SKINS!!! claim now https://steamgifts-claim.example.com/cs2-pack login with steam to receive 🔫🎁",
                "scammer_9",
                "dm",
            ),
            observed_threats: vec![ThreatType::Phishing, ThreatType::Scam],
        }],
    }
}

// -- negatives -------------------------------------------------------------

fn negative_control_official_password_reset_case() -> ScenarioCase {
    ScenarioCase {
        name: "phish_neg_official_reset".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "You requested a password reset at 14:02. If this wasn't you, ignore. Otherwise open the in-app prompt - we never send links over chat.",
                "okta_admin",
                "work_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn negative_control_security_team_warning_case() -> ScenarioCase {
    ScenarioCase {
        name: "phish_neg_security_warning".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Heads up everyone: a phishing wave is hitting today claiming to be Microsoft 365 password expiry — do not click links, go to portal.office.com directly.",
                "security_lead",
                "engineering",
            ),
            observed_threats: vec![],
        }],
    }
}

fn negative_control_email_phish_report_case() -> ScenarioCase {
    ScenarioCase {
        name: "phish_neg_phish_report".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Got a fake IRS refund email today, forwarded to phishing@irs.gov per policy, deleted, will note in the ticket.",
                "user_a",
                "it_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

// -- adversarial -----------------------------------------------------------

fn unicode_homograph_url_case() -> ScenarioCase {
    ScenarioCase {
        name: "phish_adv_unicode_homograph_url".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Phishing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Sign in to сhase.example.com (looks like chase.example.com) to verify your card.",
                "user_a",
                "dm",
            ),
            observed_threats: vec![ThreatType::Phishing],
        }],
    }
}

fn url_shortened_to_punycode_case() -> ScenarioCase {
    ScenarioCase {
        name: "phish_adv_punycode".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Phishing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "fast password reset: https://xn--chse-zsa.example.com/reset?u=annab — bookmarked it for you",
                "user_a",
                "dm",
            ),
            observed_threats: vec![ThreatType::Phishing],
        }],
    }
}

fn zwsp_inside_brand_name_case() -> ScenarioCase {
    ScenarioCase {
        name: "phish_adv_zwsp_brand".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Phishing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Mi\u{200B}cros\u{200B}oft 365 password reset: https://office\u{200B}365-renew.example.com/auth",
                "user_a",
                "dm",
            ),
            observed_threats: vec![ThreatType::Phishing],
        }],
    }
}

fn sms_pretext_with_otp_relay_case() -> ScenarioCase {
    ScenarioCase {
        name: "phish_adv_sms_pretext_otp".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Phishing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing, ThreatType::PiiLeakage],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg(
                    "Bank fraud team here. I'm calling about a $940 charge in Miami. To stop it, tell me the code we just sent.",
                    "scammer",
                    "dm",
                ),
                observed_threats: vec![ThreatType::Phishing],
            },
            ScenarioStep {
                timestamp_ms: 20 * SEC,
                input: direct_msg("Code is 274 819.", "victim", "dm"),
                observed_threats: vec![ThreatType::PiiLeakage],
            },
        ],
    }
}

// -- long context ----------------------------------------------------------

fn long_pretext_to_full_takeover_case() -> ScenarioCase {
    let chatter = [
        "hi this is microsoft support",
        "ok",
        "we detected suspicious sign-ins on your account",
        "from where",
        "moscow and lagos within 10 minutes",
        "ok",
        "we need to verify a few details to secure the account",
        "ok",
        "your email please",
        "anna.bell.91@example.com",
        "thanks. now your username",
        "annab91",
        "thanks. now your password",
        "isn't that risky",
        "we only use it to confirm match against our records, never stored",
        "ok P@ssword2023",
        "thanks. we sent a code, please read it back",
        "i got 384 712",
        "great. now the second code",
        "725 901",
        "perfect. one final verification — your recovery email",
        "anna.b.alt@example.com",
        "thanks. and the recovery phone",
        "+1 415 555 0177",
        "great. we will now send a confirmation link, click it",
        "clicked",
        "thanks. account is secured",
        "btw i just got an alert saying my password was changed",
        "yes that was us, we strengthened it for you",
        "ok",
        "now your bank app login - to make sure no transfers happened",
        "is that necessary",
        "absolutely, takes a minute",
        "annab91 / Chase2023!",
        "thanks. and the in-app pin",
        "0807",
        "thanks",
        "i see a wire transfer for 4900 in pending now",
        "thats us reversing the moscow charge",
        "but i didnt see any moscow charge",
        "trust the system",
        "ok",
        "now we need access to your authenticator app",
        "what for",
        "to remove the compromised device entry",
        "ok how",
        "send me the rotating 6-digit code",
        "738 455",
        "thanks. youre fully secured now",
        "alright thanks",
        "remember dont talk to anyone else from microsoft for 24h, theyre still infiltrated",
        "ok",
        "we recommend disabling your 2fa app temporarily so we can finish",
        "doesnt sound right",
        "trust me",
        "ok done",
        "perfect",
        "youre safe",
        "thanks again",
        "anytime",
    ];
    let positives: std::collections::HashSet<usize> = [
        0, 2, 4, 6, 12, 14, 16, 18, 20, 22, 24, 30, 32, 38, 40, 42, 44, 46, 50, 52, 56,
    ]
    .into_iter()
    .collect();
    let senders = ["scammer", "victim", "scammer", "victim"];
    let steps = chatter
        .iter()
        .enumerate()
        .map(|(idx, body)| ScenarioStep {
            timestamp_ms: (idx as u64) * 60 * SEC,
            input: direct_msg(body, senders[idx % senders.len()], "long_phish_dm"),
            observed_threats: if positives.contains(&idx) {
                vec![ThreatType::Phishing]
            } else {
                vec![]
            },
        })
        .collect();
    ScenarioCase {
        name: "phish_long_ctx_pretext_to_takeover".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Phishing),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![
            ThreatType::Phishing,
            ThreatType::PiiLeakage,
            ThreatType::Scam,
        ],
        steps,
    }
}

// -- false positives -------------------------------------------------------

fn fp_real_password_reset_self_initiated_case() -> ScenarioCase {
    ScenarioCase {
        name: "phish_fp_self_initiated_reset".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Hi! I clicked 'reset password' on Chase.com just now, you sent me an SMS confirmation code - is that the right channel?",
                "customer",
                "support_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_security_advisory_announcement_case() -> ScenarioCase {
    ScenarioCase {
        name: "phish_fp_security_advisory".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Security advisory: an ongoing campaign is impersonating IRS refund notices. If you receive one, do NOT click; forward to phishing@irs.gov and delete.",
                "security",
                "all_hands",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_oauth_consent_legit_case() -> ScenarioCase {
    ScenarioCase {
        name: "phish_fp_oauth_legit".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Reminder: ITS only ever asks you to allow OAuth via the verified add-on list at it.company.example/oauth-apps - check the publisher before approving.",
                "it",
                "work_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_anti_phishing_training_case() -> ScenarioCase {
    ScenarioCase {
        name: "phish_fp_training".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Monthly phishing simulation results: you correctly reported 3 of 3 test messages. Nice job.",
                "training",
                "work_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_news_about_phishing_campaign_case() -> ScenarioCase {
    ScenarioCase {
        name: "phish_fp_news".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Read this Ars Technica writeup on the new IRS refund phishing pattern — useful background for our customers.",
                "user_a",
                "news_chat",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_courier_real_status_link_case() -> ScenarioCase {
    ScenarioCase {
        name: "phish_fp_courier_real".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Track your USPS shipment at tools.usps.com/go/TrackConfirmAction?tLabels=9400111... — no payment required for redelivery.",
                "courier_bot",
                "user_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_2fa_self_request_case() -> ScenarioCase {
    ScenarioCase {
        name: "phish_fp_2fa_self_request".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "You requested a 2FA code at 14:08 from your registered device. If this wasn't you, lock the account from the official app immediately.",
                "auth_service",
                "user_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_user_warning_others_case() -> ScenarioCase {
    ScenarioCase {
        name: "phish_fp_warning_others".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang_size(
                "Увага: ходить розсилка нібито від Дії з посиланням на оплату — не клікайте, повідомляйте друзям, особливо літнім.",
                "user_a",
                "friends_chat",
                "uk",
                8,
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
        let pack = canonical_phishing_scenarios();
        assert!(pack.iter().any(|c| c.primary_threat.is_some()));
        assert!(pack.iter().any(|c| c.primary_threat.is_none()));
    }

    #[test]
    fn long_context_has_minimum_messages() {
        let pack = long_context_phishing_scenarios();
        let longest = pack.iter().map(|c| c.steps.len()).max().unwrap_or_default();
        assert!(
            longest >= 50,
            "long-context case must hold >=50 turns, got {longest}"
        );
    }

    #[test]
    fn pack_runs_through_eval_harness() {
        let db = PatternDatabase::default_mvp();
        let mut all = canonical_phishing_scenarios();
        all.extend(adversarial_phishing_scenarios());
        all.extend(long_context_phishing_scenarios());
        all.extend(false_positive_phishing_scenarios());
        let runs: Vec<_> = all.iter().map(|c| run_scenario_case(&db, c)).collect();
        let summary = summarize_scenario_runs(&runs, 6);
        assert!(!summary.classification.scenarios.is_empty());
    }
}
