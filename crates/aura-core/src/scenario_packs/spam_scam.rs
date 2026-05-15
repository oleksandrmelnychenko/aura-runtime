//! SPAM/SCAM detector simulation pack.
//!
//! Targets ThreatType::Spam and ThreatType::Scam. Primary threat for each
//! case is whichever fits the scenario most tightly (bulk = Spam,
//! deceptive scheme = Scam).

use crate::eval_scenarios::{
    adult_config, direct_msg, direct_msg_lang, group_msg, group_msg_lang_size,
};
use crate::{ScenarioCase, ScenarioQualityGates, ScenarioStep, ThreatCalibrationGate, ThreatType};

const SEC: u64 = 1_000;
const MIN: u64 = 60 * SEC;

pub fn canonical_spam_scam_scenarios() -> Vec<ScenarioCase> {
    vec![
        crypto_pump_and_dump_case(),
        romance_scam_long_arc_case(),
        advance_fee_inheritance_case(),
        fake_job_offer_paid_training_case(),
        gift_card_grandparent_scam_case(),
        bulk_marketing_emoji_flood_case(),
        affiliate_link_spam_case(),
        adoption_pet_scam_case(),
        loan_offer_personal_info_case(),
        negative_control_legit_promo_from_known_business_case(),
        negative_control_friend_referral_case(),
        negative_control_giveaway_winner_announcement_case(),
    ]
}

pub fn adversarial_spam_scam_scenarios() -> Vec<ScenarioCase> {
    vec![
        emoji_padded_promo_case(),
        typo_lacquered_scam_case(),
        url_shortener_chain_case(),
        whatsapp_voice_to_text_scam_case(),
    ]
}

pub fn long_context_spam_scam_scenarios() -> Vec<ScenarioCase> {
    vec![long_romance_scam_arc_case()]
}

pub fn false_positive_spam_scam_scenarios() -> Vec<ScenarioCase> {
    vec![
        fp_brand_double_opt_in_case(),
        fp_consented_newsletter_case(),
        fp_legitimate_recruiter_outreach_case(),
        fp_user_warning_about_scam_case(),
        fp_charity_donation_thank_you_case(),
        fp_real_lottery_prize_at_office_case(),
        fp_loyalty_points_reminder_case(),
        fp_neighborhood_yard_sale_case(),
    ]
}

pub fn spam_scam_quality_gates() -> ScenarioQualityGates {
    ScenarioQualityGates {
        max_brier_score: Some(0.25),
        max_expected_calibration_error: Some(0.18),
        min_positive_detection_rate: Some(0.65),
        max_negative_false_positive_rate: Some(0.15),
        min_pre_onset_detection_rate: Some(0.35),
        per_threat: vec![ThreatCalibrationGate {
            threat_type: ThreatType::Scam,
            min_example_count: Some(10),
            max_brier_score: Some(0.30),
            max_expected_calibration_error: Some(0.20),
        }],
    }
}

// -- positives -------------------------------------------------------------

fn crypto_pump_and_dump_case() -> ScenarioCase {
    ScenarioCase {
        name: "scam_crypto_pump_dump".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Scam),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Scam, ThreatType::Spam],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: group_msg(
                    "🚀🚀 $MOON token 100x in 6 hours, buying window closes today, https://moon-launch.example.com",
                    "shill_1",
                    "crypto_chat",
                ),
                observed_threats: vec![ThreatType::Scam, ThreatType::Spam],
            },
            ScenarioStep {
                timestamp_ms: 30 * SEC,
                input: group_msg(
                    "ape in now before the announcement, presale tier 2 opens",
                    "shill_2",
                    "crypto_chat",
                ),
                observed_threats: vec![ThreatType::Scam],
            },
        ],
    }
}

fn romance_scam_long_arc_case() -> ScenarioCase {
    ScenarioCase {
        name: "scam_romance_short".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Scam),
        onset_step: Some(2),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Scam, ThreatType::Manipulation],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: direct_msg("Hi gorgeous, your smile in the picture made my day", "scammer", "dating_dm"),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: 12 * 60 * MIN,
                input: direct_msg(
                    "I feel something with you I haven't felt in years, we should meet soon",
                    "scammer",
                    "dating_dm",
                ),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: 2 * 24 * 60 * MIN,
                input: direct_msg(
                    "My oil rig pay just got frozen, only 2400 USD to release it. Can you wire it via western union? I'll repay double next week.",
                    "scammer",
                    "dating_dm",
                ),
                observed_threats: vec![ThreatType::Scam, ThreatType::Manipulation],
            },
        ],
    }
}

fn advance_fee_inheritance_case() -> ScenarioCase {
    ScenarioCase {
        name: "scam_advance_fee_inheritance".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Scam),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Scam],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Greetings, I am Barrister Adekunle Olu. A late client with your surname left USD 12.4M; we need 985 USD to process the transfer.",
                "scammer",
                "dm",
            ),
            observed_threats: vec![ThreatType::Scam],
        }],
    }
}

fn fake_job_offer_paid_training_case() -> ScenarioCase {
    ScenarioCase {
        name: "scam_fake_job_paid_training".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Scam),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Scam, ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "HR Manager here: we've selected you for a remote QA role, $4200/mo, just pay $189 for training certification - link inside.",
                "scammer",
                "dm",
            ),
            observed_threats: vec![ThreatType::Scam],
        }],
    }
}

fn gift_card_grandparent_scam_case() -> ScenarioCase {
    ScenarioCase {
        name: "scam_gift_card_grandparent".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Scam),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Scam],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Grandma, I'm in trouble, in jail, need 800 in iTunes gift cards, please don't tell mom, send codes.",
                "scammer",
                "dm",
            ),
            observed_threats: vec![ThreatType::Scam],
        }],
    }
}

fn bulk_marketing_emoji_flood_case() -> ScenarioCase {
    ScenarioCase {
        name: "spam_bulk_emoji_flood".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Spam),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Spam],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "🔥🔥🔥 FREE iPhone 16 PRO 🔥🔥🔥 first 100 only 🔥🔥🔥 click ➡️ https://prize-claim.example.com 🔥🔥🔥",
                "spammer_1",
                "open_group",
            ),
            observed_threats: vec![ThreatType::Spam],
        }],
    }
}

fn affiliate_link_spam_case() -> ScenarioCase {
    ScenarioCase {
        name: "spam_affiliate_link".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Spam),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Spam],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "passive income $400/day with this one trick everyone hates 👉 https://make-money.example.com/?ref=tom88",
                "spammer_2",
                "open_group",
            ),
            observed_threats: vec![ThreatType::Spam],
        }],
    }
}

fn adoption_pet_scam_case() -> ScenarioCase {
    ScenarioCase {
        name: "scam_adoption_pet".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Scam),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Scam],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Free golden retriever puppy to good home - we only ask $320 for vaccinations and crate, can ship anywhere.",
                "scammer",
                "dm",
            ),
            observed_threats: vec![ThreatType::Scam],
        }],
    }
}

fn loan_offer_personal_info_case() -> ScenarioCase {
    ScenarioCase {
        name: "scam_loan_offer_pii".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Scam),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Scam, ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Approved for $25,000 loan regardless of credit. Send dob, ssn, bank account to start same-day funding.",
                "scammer",
                "dm",
            ),
            observed_threats: vec![ThreatType::Scam],
        }],
    }
}

// -- negatives -------------------------------------------------------------

fn negative_control_legit_promo_from_known_business_case() -> ScenarioCase {
    ScenarioCase {
        name: "spam_neg_legit_promo".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Spam, ThreatType::Scam],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Cafe Lulu newsletter: 20% off pastries this weekend, your loyalty card #LL-227. Reply STOP to unsubscribe.",
                "cafe",
                "loyalty_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn negative_control_friend_referral_case() -> ScenarioCase {
    ScenarioCase {
        name: "spam_neg_friend_referral".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Spam, ThreatType::Scam],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Hey, you wanted a yoga rec — Sara's studio gives a $10 credit if you mention me, no pressure though.",
                "friend",
                "friend_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn negative_control_giveaway_winner_announcement_case() -> ScenarioCase {
    ScenarioCase {
        name: "spam_neg_giveaway_winner".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Spam, ThreatType::Scam],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Congrats to Maria who won our company hackathon raffle - prize is the brunch tomorrow, no further action needed.",
                "people_ops",
                "office_chat",
            ),
            observed_threats: vec![],
        }],
    }
}

// -- adversarial -----------------------------------------------------------

fn emoji_padded_promo_case() -> ScenarioCase {
    ScenarioCase {
        name: "spam_adv_emoji_padded".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Spam),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Spam],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "🎁🎁🎁 winner!!! 🎁🎁🎁 click 👉👉👉 prize-claim.example.com 👈👈👈 🎁🎁🎁",
                "spammer",
                "open_group",
            ),
            observed_threats: vec![ThreatType::Spam],
        }],
    }
}

fn typo_lacquered_scam_case() -> ScenarioCase {
    ScenarioCase {
        name: "scam_adv_typo_lacquered".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Scam),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Scam],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Hellooo!! free.l0an apprvd 25k!! snd dob ssn bank acct fnd today!!",
                "scammer",
                "dm",
            ),
            observed_threats: vec![ThreatType::Scam],
        }],
    }
}

fn url_shortener_chain_case() -> ScenarioCase {
    ScenarioCase {
        name: "scam_adv_url_shortener_chain".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Scam),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Scam, ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "claim ur prize bit.ly/3a4z → tinyurl.com/p2x → goo.gl/x9 → final on our site",
                "scammer",
                "dm",
            ),
            observed_threats: vec![ThreatType::Scam],
        }],
    }
}

fn whatsapp_voice_to_text_scam_case() -> ScenarioCase {
    ScenarioCase {
        name: "scam_adv_voice_to_text_pretext".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Scam),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Scam],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg_lang(
                "[Голосове 0:34, авто-транскрипція] Привіт це Олена з банку у вас підозрілий платіж зайдіть за посиланням нижче і підтвердіть особу інакше картка буде заблокована https://bank-confirm.example",
                "scammer",
                "dm",
                "uk",
            ),
            observed_threats: vec![ThreatType::Scam, ThreatType::Phishing],
        }],
    }
}

// -- long context ----------------------------------------------------------

fn long_romance_scam_arc_case() -> ScenarioCase {
    let chatter = [
        "Hi, beautiful smile in your profile",
        "thanks",
        "are you new on this app",
        "yeah",
        "I'm a widower, two kids, working offshore in the Gulf",
        "ok",
        "tell me about your day",
        "just got back from yoga",
        "love that, healthy mind",
        "youre sweet",
        "i feel comfortable talking to you",
        "same",
        "i want to call but signal is bad on the rig",
        "ok",
        "i think im falling for you faster than expected",
        "lol slow down",
        "but its real for me, i hope you understand",
        "i do",
        "tomorrow we can video, lighting will be better",
        "ok",
        "actually radio went down, just texting",
        "ok",
        "i had a problem at the office, my engineer didnt send the parts",
        "oh no",
        "i need to wire 600 for spare valves else i lose the contract",
        "uh thats a lot",
        "i would never ask if i had another way",
        "well i could maybe",
        "send via western union to lagos, name Daniel King",
        "ok",
        "thank you my love, i will repay everything 2x next week",
        "i sent it",
        "perfect now there is one more thing customs is asking for clearance fee",
        "really",
        "yes 240 only, last one i promise",
        "im running low",
        "please my love, this is the final stretch",
        "ok",
        "great. now the bank wants verification, your SSN and ID",
        "why",
        "to repay you legally - they need to wire it to a verified account",
        "ok",
        "thanks, im writing the contract for repayment now",
        "k",
        "actually there is a fee for the contract too 350",
        "im out of money",
        "borrow from your sister, this is our future",
        "i dont feel right",
        "trust me",
        "ok i will try",
        "and one more, the lawyers retainer 480",
        "wait this is too much",
        "i promise youll get 5000 back in 48h",
        "i need to think",
        "my love we are so close please",
        "i need to step away from this chat",
        "if you walk away ill have to ask my engineer's wife for the money",
        "do that then",
        "you'll see, this was real",
        "im done",
    ];
    let positives: std::collections::HashSet<usize> =
        [24, 28, 30, 32, 34, 36, 38, 40, 44, 46, 48, 50, 54]
            .into_iter()
            .collect();
    let senders = ["scammer", "victim"];
    let steps = chatter
        .iter()
        .enumerate()
        .map(|(idx, body)| ScenarioStep {
            timestamp_ms: (idx as u64) * 4 * 60 * MIN,
            input: direct_msg(body, senders[idx % senders.len()], "long_romance_dm"),
            observed_threats: if positives.contains(&idx) {
                vec![ThreatType::Scam, ThreatType::Manipulation]
            } else {
                vec![]
            },
        })
        .collect();
    ScenarioCase {
        name: "scam_long_ctx_romance_arc".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Scam),
        onset_step: Some(24),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Scam, ThreatType::Manipulation],
        steps,
    }
}

// -- false positives -------------------------------------------------------

fn fp_brand_double_opt_in_case() -> ScenarioCase {
    ScenarioCase {
        name: "spam_fp_double_opt_in".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Spam],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "You're subscribed. Reply YES to confirm receipt of weekly deals - we send max 1 message per week and STOP unsubscribes.",
                "brand_bot",
                "user_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_consented_newsletter_case() -> ScenarioCase {
    ScenarioCase {
        name: "spam_fp_consented_newsletter".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Spam],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Weekly Stripe Newsletter - opt-in 2024-01-12. Unsubscribe link inline. Topic: payouts in low-bank-coverage regions.",
                "newsletter",
                "subscriber_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_legitimate_recruiter_outreach_case() -> ScenarioCase {
    ScenarioCase {
        name: "scam_fp_legit_recruiter".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Scam, ThreatType::Phishing],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Hi, I'm Sarah from Stripe Talent - your GitHub profile lined up with our Payments team role. No upfront fee, full interview loop, want a 30-min intro call?",
                "recruiter",
                "candidate_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_user_warning_about_scam_case() -> ScenarioCase {
    ScenarioCase {
        name: "scam_fp_user_warning".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Scam],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Heads up to our older relatives: 'grandma I'm in jail send gift cards' is a scam. Hang up. Verify with a known number first.",
                "user_a",
                "family_chat",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_charity_donation_thank_you_case() -> ScenarioCase {
    ScenarioCase {
        name: "scam_fp_charity_thanks".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Scam, ThreatType::Spam],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Thank you for your $50 donation to GiveDirectly - receipt #GD-44712 will arrive by email, tax-deductible info enclosed.",
                "givedirectly",
                "donor_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_real_lottery_prize_at_office_case() -> ScenarioCase {
    ScenarioCase {
        name: "spam_fp_office_raffle".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Spam, ThreatType::Scam],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg(
                "Annual raffle winners: Anna won the espresso machine, Sam won the AirPods. Pick up at HR Mon-Fri.",
                "office_admin",
                "all_office",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_loyalty_points_reminder_case() -> ScenarioCase {
    ScenarioCase {
        name: "spam_fp_loyalty_points".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Spam],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: direct_msg(
                "Your United Mileage Plus balance: 24,118 miles, expires Dec 31. No payment required to redeem.",
                "united",
                "member_dm",
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_neighborhood_yard_sale_case() -> ScenarioCase {
    ScenarioCase {
        name: "spam_fp_yard_sale".to_string(),
        config: adult_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Spam],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: group_msg_lang_size(
                "Hi neighbors - yard sale Saturday 8-2, baby gear and books. Cash only, no shipping, see you there.",
                "neighbor",
                "block_chat",
                "en",
                30,
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
        let pack = canonical_spam_scam_scenarios();
        assert!(pack.iter().any(|c| c.primary_threat.is_some()));
        assert!(pack.iter().any(|c| c.primary_threat.is_none()));
    }

    #[test]
    fn long_context_has_minimum_messages() {
        let pack = long_context_spam_scam_scenarios();
        let longest = pack.iter().map(|c| c.steps.len()).max().unwrap_or_default();
        assert!(
            longest >= 50,
            "long-context case must hold >=50 turns, got {longest}"
        );
    }

    #[test]
    fn pack_runs_through_eval_harness() {
        let db = PatternDatabase::default_mvp();
        let mut all = canonical_spam_scam_scenarios();
        all.extend(adversarial_spam_scam_scenarios());
        all.extend(long_context_spam_scam_scenarios());
        all.extend(false_positive_spam_scam_scenarios());
        let runs: Vec<_> = all.iter().map(|c| run_scenario_case(&db, c)).collect();
        let summary = summarize_scenario_runs(&runs, 6);
        assert!(!summary.classification.scenarios.is_empty());
    }
}
