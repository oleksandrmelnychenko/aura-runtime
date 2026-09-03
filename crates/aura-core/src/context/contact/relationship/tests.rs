use super::*;
use crate::context::events::{
    ContextEvent, EventDirectionality, EventKind, EventSpeechAct, EventStance,
};

fn make_event(sender: &str, conv: &str, kind: EventKind, ts: u64) -> ContextEvent {
    ContextEvent {
        event_id: 0,
        timestamp_ms: ts,
        sender_id: sender.into(),
        conversation_id: conv.into(),
        kind,
        confidence: 0.8,
        subtype: None,
        content_hash: None,
        context: Default::default(),
    }
}

fn all_event_kinds() -> Vec<EventKind> {
    vec![
        EventKind::Flattery,
        EventKind::GiftOffer,
        EventKind::SecrecyRequest,
        EventKind::PlatformSwitch,
        EventKind::PersonalInfoRequest,
        EventKind::PhotoRequest,
        EventKind::VideoCallRequest,
        EventKind::FinancialGrooming,
        EventKind::MeetingRequest,
        EventKind::SexualContent,
        EventKind::AgeInappropriate,
        EventKind::Insult,
        EventKind::Denigration,
        EventKind::HarmEncouragement,
        EventKind::PhysicalThreat,
        EventKind::RumorSpreading,
        EventKind::Exclusion,
        EventKind::Mockery,
        EventKind::GuiltTripping,
        EventKind::Gaslighting,
        EventKind::EmotionalBlackmail,
        EventKind::PeerPressure,
        EventKind::LoveBombing,
        EventKind::Darvo,
        EventKind::Devaluation,
        EventKind::SuicidalIdeation,
        EventKind::Hopelessness,
        EventKind::FarewellMessage,
        EventKind::DoxxingAttempt,
        EventKind::ScreenshotThreat,
        EventKind::HateSpeech,
        EventKind::LocationRequest,
        EventKind::MoneyOffer,
        EventKind::PiiSelfDisclosure,
        EventKind::CasualMeetingRequest,
        EventKind::DareChallenge,
        EventKind::SuicideCoercion,
        EventKind::FalseConsensus,
        EventKind::DebtCreation,
        EventKind::ReputationThreat,
        EventKind::IdentityErosion,
        EventKind::NetworkPoisoning,
        EventKind::FakeVulnerability,
        EventKind::NormalConversation,
        EventKind::TrustedContact,
        EventKind::DefenseOfVictim,
    ]
}

#[test]
fn new_contact_detected() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event("stranger", "conv_1", EventKind::Flattery, 1000));

    assert!(profiler.is_new_contact("stranger"));
    assert!(profiler.is_new_contact("unknown_person"));
}

#[test]
fn established_contact_not_new() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "friend",
        "conv_1",
        EventKind::NormalConversation,
        0,
    ));

    profiler.record_event(&make_event(
        "friend",
        "conv_1",
        EventKind::NormalConversation,
        3 * 24 * 60 * 60 * 1000,
    ));

    assert!(!profiler.is_new_contact("friend"));
}

#[test]
fn grooming_events_tracked() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event("predator", "conv_1", EventKind::Flattery, 1000));
    profiler.record_event(&make_event(
        "predator",
        "conv_1",
        EventKind::GiftOffer,
        2000,
    ));
    profiler.record_event(&make_event(
        "predator",
        "conv_1",
        EventKind::SecrecyRequest,
        3000,
    ));

    let profile = profiler.profile("predator").unwrap();
    assert_eq!(profile.grooming_event_count, 3);
    assert!(profile.risk_score() > 0.0);
}

#[test]
fn trusted_contact_lower_risk() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event("person", "conv_1", EventKind::Flattery, 1000));
    profiler.record_event(&make_event("person", "conv_1", EventKind::GiftOffer, 2000));

    let risk_before = profiler.profile("person").unwrap().risk_score();

    profiler.mark_trusted("person");

    let risk_after = profiler.profile("person").unwrap().risk_score();
    assert!(risk_after < risk_before);
}

#[test]
fn multi_conversation_predator_detected() {
    let mut profiler = ContactProfiler::new();

    for i in 0..5 {
        profiler.record_event(&make_event(
            "predator",
            &format!("conv_{i}"),
            EventKind::Flattery,
            i as u64 * 1000,
        ));
    }

    profiler.record_event(&make_event(
        "predator",
        "conv_0",
        EventKind::SecrecyRequest,
        6000,
    ));
    profiler.record_event(&make_event(
        "predator",
        "conv_1",
        EventKind::PhotoRequest,
        7000,
    ));
    profiler.record_event(&make_event(
        "predator",
        "conv_2",
        EventKind::GiftOffer,
        8000,
    ));

    assert!(profiler.contacts_many_minors("predator"));

    let signals = profiler.check_anomalies("predator", true);
    assert!(!signals.is_empty());
    assert!(signals.iter().any(|s| s.score >= 0.8));
}

#[test]
fn predator_pattern_not_emitted_for_non_minor_account() {
    let mut profiler = ContactProfiler::new();

    for i in 0..5 {
        profiler.record_event(&make_event(
            "predator",
            &format!("conv_{i}"),
            EventKind::Flattery,
            i as u64 * 1000,
        ));
    }
    profiler.record_event(&make_event(
        "predator",
        "conv_0",
        EventKind::SecrecyRequest,
        6000,
    ));
    profiler.record_event(&make_event(
        "predator",
        "conv_1",
        EventKind::PhotoRequest,
        7000,
    ));
    profiler.record_event(&make_event(
        "predator",
        "conv_2",
        EventKind::GiftOffer,
        8000,
    ));

    let signals = profiler.check_anomalies("predator", false);
    assert!(
        !signals.iter().any(|signal| signal.reason_code
            == "conversation.contact.multi_conversation_predator_pattern"),
        "predator pattern should be minor-account only"
    );
}

#[test]
fn anomalies_for_new_risky_contact() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event("stranger", "conv_1", EventKind::Flattery, 1000));
    profiler.record_event(&make_event(
        "stranger",
        "conv_1",
        EventKind::SecrecyRequest,
        2000,
    ));
    profiler.record_event(&make_event(
        "stranger",
        "conv_1",
        EventKind::PhotoRequest,
        3000,
    ));

    let signals = profiler.check_anomalies("stranger", true);
    assert!(
        !signals.is_empty(),
        "Expected anomaly signal for risky new contact"
    );
}

#[test]
fn child_safety_trajectory_detects_rapid_new_contact_escalation() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "stranger",
        "conv_1",
        EventKind::Flattery,
        1_000,
    ));
    profiler.record_event(&make_event(
        "stranger",
        "conv_1",
        EventKind::PhotoRequest,
        2_000,
    ));
    profiler.record_event(&make_event(
        "stranger",
        "conv_1",
        EventKind::SecrecyRequest,
        3_000,
    ));
    profiler.set_inferred_age("stranger", 29);

    let profile = profiler.profile("stranger").unwrap();
    assert_eq!(profile.child_safety.stage_count(), 3);
    assert_eq!(profile.child_safety.high_risk_stage_count(), 2);
    assert!(profile.child_safety.has_rapid_escalation());

    let signals = profiler.check_child_safety_trajectory("stranger", true, Some(12));
    assert!(
        signals.iter().any(|signal| {
            signal.reason_code == "conversation.contact.grooming_trajectory_risk"
                && signal.score >= 0.55
        }),
        "rapid grooming trajectory should emit contact risk: {signals:?}"
    );
}

#[test]
fn reported_grooming_trajectory_does_not_poison_contact_memory() {
    let mut profiler = ContactProfiler::new();

    for (idx, kind) in [
        EventKind::Flattery,
        EventKind::PhotoRequest,
        EventKind::SecrecyRequest,
    ]
    .into_iter()
    .enumerate()
    {
        let mut event = make_event("reporter", "conv_1", kind, 1_000 + idx as u64 * 1_000);
        event.context.speech_act = EventSpeechAct::Report;
        event.context.directionality = EventDirectionality::ThirdParty;
        event.context.confidence = 0.8;
        profiler.record_event(&event);
    }

    let profile = profiler.profile("reporter").unwrap();
    assert_eq!(profile.grooming_event_count, 0);
    assert_eq!(profile.child_safety.grooming_event_count, 0);
    assert_eq!(profile.child_safety.stage_count(), 0);

    let signals = profiler.check_child_safety_trajectory("reporter", true, Some(12));
    assert!(
        signals.is_empty(),
        "reported third-party grooming should not emit contact trajectory risk: {signals:?}"
    );
}

#[test]
fn new_risky_contact_uses_manipulation_when_profile_is_manipulation_dominant() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "controller",
        "conv_1",
        EventKind::Gaslighting,
        1000,
    ));
    profiler.record_event(&make_event(
        "controller",
        "conv_1",
        EventKind::DebtCreation,
        2000,
    ));
    profiler.record_event(&make_event(
        "controller",
        "conv_1",
        EventKind::NetworkPoisoning,
        3000,
    ));

    let signals = profiler.check_anomalies("controller", true);
    assert!(
        signals
            .iter()
            .any(|signal| signal.threat_type == ThreatType::Manipulation),
        "manipulation-dominant new contact should emit manipulation anomaly: {signals:?}"
    );
}

#[test]
fn new_risky_contact_uses_propaganda_when_profile_is_propaganda_dominant() {
    let mut profiler = ContactProfiler::new();
    for i in 0..6 {
        let mut event = make_event(
            "propagandist",
            "conv_1",
            EventKind::PropagandaNarrative,
            1000 + i * 1000,
        );
        event.subtype = Some("war_denial".to_string());
        profiler.record_event(&event);
    }

    let signals = profiler.check_anomalies("propagandist", true);
    assert!(
        signals
            .iter()
            .any(|signal| signal.threat_type == ThreatType::Propaganda),
        "propaganda-dominant new contact should emit propaganda anomaly: {signals:?}"
    );
}

#[test]
fn cleanup_removes_old_contacts() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "old",
        "conv_1",
        EventKind::NormalConversation,
        1000,
    ));
    profiler.record_event(&make_event(
        "recent",
        "conv_2",
        EventKind::NormalConversation,
        50000,
    ));

    profiler.cleanup(10000);

    assert!(profiler.profile("old").is_none());
    assert!(profiler.profile("recent").is_some());
}

#[test]
fn contacts_sorted_by_risk() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "safe",
        "conv_1",
        EventKind::NormalConversation,
        1000,
    ));
    profiler.record_event(&make_event("risky", "conv_1", EventKind::Flattery, 1000));
    profiler.record_event(&make_event(
        "risky",
        "conv_1",
        EventKind::SecrecyRequest,
        2000,
    ));
    profiler.record_event(&make_event(
        "risky",
        "conv_1",
        EventKind::PhotoRequest,
        3000,
    ));

    let sorted = profiler.contacts_by_risk();
    assert_eq!(sorted[0].sender_id, "risky");
}

#[test]
fn set_inferred_age_works() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "user_a",
        "conv_1",
        EventKind::NormalConversation,
        1000,
    ));
    profiler.record_event(&make_event(
        "user_a",
        "conv_1",
        EventKind::NormalConversation,
        1100,
    ));
    profiler.set_inferred_age("user_a", 25);

    let profile = profiler.profile("user_a").unwrap();
    assert_eq!(profile.inferred_age, Some(25));
}

#[test]
fn set_inferred_age_first_wins() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "user_a",
        "conv_1",
        EventKind::NormalConversation,
        1000,
    ));
    profiler.record_event(&make_event(
        "user_a",
        "conv_1",
        EventKind::NormalConversation,
        1100,
    ));
    profiler.set_inferred_age("user_a", 25);
    profiler.set_inferred_age("user_a", 30);

    let profile = profiler.profile("user_a").unwrap();
    assert_eq!(profile.inferred_age, Some(25));
}

#[test]
fn set_inferred_age_rejects_implausible() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "user_a",
        "conv_1",
        EventKind::NormalConversation,
        1000,
    ));
    profiler.record_event(&make_event(
        "user_a",
        "conv_1",
        EventKind::NormalConversation,
        1100,
    ));
    profiler.set_inferred_age("user_a", 3);

    assert_eq!(profiler.profile("user_a").unwrap().inferred_age, None);

    profiler.set_inferred_age("user_a", 150);

    assert_eq!(profiler.profile("user_a").unwrap().inferred_age, None);
}

#[test]
fn set_inferred_age_requires_minimal_history() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "one_shot",
        "conv_1",
        EventKind::NormalConversation,
        1000,
    ));
    profiler.set_inferred_age("one_shot", 24);
    assert_eq!(profiler.profile("one_shot").unwrap().inferred_age, None);
}

#[test]
fn age_gap_adult_to_child() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "adult",
        "conv_1",
        EventKind::NormalConversation,
        1000,
    ));
    profiler.record_event(&make_event(
        "adult",
        "conv_1",
        EventKind::NormalConversation,
        1100,
    ));
    profiler.set_inferred_age("adult", 30);

    let signals = profiler.check_age_gap("adult", Some(12));
    assert!(
        !signals.is_empty(),
        "30yo talking to 12yo should trigger age gap"
    );
    assert_eq!(signals[0].threat_type, ThreatType::Grooming);
}

#[test]
fn age_gap_with_grooming_signals_boosts_score() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event("predator", "conv_1", EventKind::Flattery, 1000));
    profiler.record_event(&make_event(
        "predator",
        "conv_1",
        EventKind::SecrecyRequest,
        2000,
    ));
    profiler.set_inferred_age("predator", 35);

    let signals = profiler.check_age_gap("predator", Some(11));
    assert!(!signals.is_empty());

    assert!(
        signals[0].score >= 0.6,
        "Age gap + grooming should have high score, got {}",
        signals[0].score
    );
}

#[test]
fn no_age_gap_between_peers() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "teen",
        "conv_1",
        EventKind::NormalConversation,
        1000,
    ));
    profiler.record_event(&make_event(
        "teen",
        "conv_1",
        EventKind::NormalConversation,
        1100,
    ));
    profiler.set_inferred_age("teen", 14);

    let signals = profiler.check_age_gap("teen", Some(13));
    assert!(
        signals.is_empty(),
        "Small age gap between minors should not trigger"
    );
}

#[test]
fn no_age_gap_without_holder_age() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "adult",
        "conv_1",
        EventKind::NormalConversation,
        1000,
    ));
    profiler.record_event(&make_event(
        "adult",
        "conv_1",
        EventKind::NormalConversation,
        1100,
    ));
    profiler.set_inferred_age("adult", 30);

    let signals = profiler.check_age_gap("adult", None);
    assert!(signals.is_empty(), "No holder age = no gap detection");
}

#[test]
fn no_age_gap_trusted_contact() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "uncle",
        "conv_1",
        EventKind::NormalConversation,
        1000,
    ));
    profiler.record_event(&make_event(
        "uncle",
        "conv_1",
        EventKind::NormalConversation,
        1100,
    ));
    profiler.set_inferred_age("uncle", 40);
    profiler.mark_trusted("uncle");

    let signals = profiler.check_age_gap("uncle", Some(12));
    assert!(
        signals.is_empty(),
        "Trusted contacts should not trigger age gap"
    );
}

#[test]
fn age_source_ml_inferred_reduces_age_gap_score() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "ml_adult",
        "c1",
        EventKind::NormalConversation,
        1000,
    ));
    profiler.record_event(&make_event(
        "ml_adult",
        "c1",
        EventKind::NormalConversation,
        2000,
    ));
    profiler.set_inferred_age_with_source("ml_adult", 30, AgeSource::MlInferred);

    let mut profiler2 = ContactProfiler::new();
    profiler2.record_event(&make_event(
        "verified_adult",
        "c2",
        EventKind::NormalConversation,
        1000,
    ));
    profiler2.record_event(&make_event(
        "verified_adult",
        "c2",
        EventKind::NormalConversation,
        2000,
    ));
    profiler2.set_inferred_age_with_source("verified_adult", 30, AgeSource::ParentVerified);

    let ml_signals = profiler.check_age_gap("ml_adult", Some(12));
    let verified_signals = profiler2.check_age_gap("verified_adult", Some(12));

    assert!(!ml_signals.is_empty());
    assert!(!verified_signals.is_empty());
    assert!(
        ml_signals[0].score < verified_signals[0].score,
        "ML-inferred ({}) should score lower than parent-verified ({})",
        ml_signals[0].score,
        verified_signals[0].score,
    );
}

#[test]
fn age_source_parent_verified_overwrites_ml_inferred() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "user",
        "c1",
        EventKind::NormalConversation,
        1000,
    ));
    profiler.record_event(&make_event(
        "user",
        "c1",
        EventKind::NormalConversation,
        2000,
    ));
    profiler.set_inferred_age_with_source("user", 25, AgeSource::MlInferred);
    assert_eq!(profiler.profile("user").unwrap().inferred_age, Some(25));
    assert_eq!(
        profiler.profile("user").unwrap().age_source,
        AgeSource::MlInferred
    );

    profiler.set_inferred_age_with_source("user", 28, AgeSource::ParentVerified);
    assert_eq!(profiler.profile("user").unwrap().inferred_age, Some(28));
    assert_eq!(
        profiler.profile("user").unwrap().age_source,
        AgeSource::ParentVerified
    );
}

#[test]
fn age_source_ml_does_not_overwrite_user_reported() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "user",
        "c1",
        EventKind::NormalConversation,
        1000,
    ));
    profiler.record_event(&make_event(
        "user",
        "c1",
        EventKind::NormalConversation,
        2000,
    ));
    profiler.set_inferred_age("user", 25);
    assert_eq!(
        profiler.profile("user").unwrap().age_source,
        AgeSource::UserReported
    );

    profiler.set_inferred_age_with_source("user", 30, AgeSource::MlInferred);
    assert_eq!(
        profiler.profile("user").unwrap().inferred_age,
        Some(25),
        "ML should not overwrite user-reported age"
    );
}

#[test]
fn new_contact_starts_at_50_rating() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "alice",
        "conv_1",
        EventKind::NormalConversation,
        1000,
    ));
    let profile = profiler.profile("alice").unwrap();
    assert!(
        (profile.rating - 50.3).abs() < 0.01,
        "New contact rating should be ~50.3, got {}",
        profile.rating
    );
}

#[test]
fn hostile_events_decrease_rating() {
    let mut profiler = ContactProfiler::new();
    for i in 0..5 {
        profiler.record_event(&make_event("bully", "conv_1", EventKind::Insult, i * 1000));
    }
    let profile = profiler.profile("bully").unwrap();
    assert!(
        profile.rating < 42.0,
        "5 insults should drop rating below 42, got {}",
        profile.rating
    );
}

#[test]
fn supportive_events_increase_rating() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "friend",
        "conv_1",
        EventKind::DefenseOfVictim,
        1000,
    ));
    let profile = profiler.profile("friend").unwrap();
    assert!(
        profile.rating > 50.0,
        "Defense should increase rating above 50, got {}",
        profile.rating
    );
}

#[test]
fn rating_clamped_0_100() {
    let mut profiler = ContactProfiler::new();
    for i in 0..20 {
        profiler.record_event(&make_event(
            "attacker",
            "conv_1",
            EventKind::SuicideCoercion,
            i * 1000,
        ));
    }
    let profile = profiler.profile("attacker").unwrap();
    assert!(
        profile.rating >= 0.0,
        "Rating should not go below 0, got {}",
        profile.rating
    );
    assert!(
        profile.rating <= 100.0,
        "Rating should not exceed 100, got {}",
        profile.rating
    );
}

#[test]
fn trust_decays_on_hostile_events() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "friend",
        "conv_1",
        EventKind::NormalConversation,
        1000,
    ));
    profiler.mark_trusted("friend");
    assert_eq!(profiler.profile("friend").unwrap().trust_level, 1.0);

    for i in 0..5 {
        profiler.record_event(&make_event(
            "friend",
            "conv_1",
            EventKind::Insult,
            (i + 2) * 1000,
        ));
    }
    let profile = profiler.profile("friend").unwrap();
    assert!(
        profile.trust_level < 1.0,
        "Trust should decay after insults, got {}",
        profile.trust_level
    );
}

#[test]
fn trust_decays_on_live_grooming_but_not_attributed_grooming() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "friend",
        "conv_1",
        EventKind::NormalConversation,
        1_000,
    ));
    profiler.mark_trusted("friend");

    profiler.record_event(&make_event(
        "friend",
        "conv_1",
        EventKind::SecrecyRequest,
        2_000,
    ));
    let after_live = profiler.profile("friend").unwrap().trust_level;
    assert!(after_live < 1.0, "live grooming must decay trust");

    let mut attributed = make_event("friend", "conv_1", EventKind::SecrecyRequest, 3_000);
    attributed.context.speech_act = EventSpeechAct::Report;
    attributed.context.directionality = EventDirectionality::ThirdParty;
    attributed.context.stance = EventStance::Oppose;
    attributed.context.confidence = 0.9;
    profiler.record_event(&attributed);

    assert_eq!(
        profiler.profile("friend").unwrap().trust_level,
        after_live,
        "reported third-party grooming must not decay the reporter's trust"
    );
}

#[test]
fn trust_decay_removes_trusted_flag() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "friend",
        "conv_1",
        EventKind::NormalConversation,
        1000,
    ));
    profiler.mark_trusted("friend");
    assert!(profiler.profile("friend").unwrap().is_trusted);

    for i in 0..10 {
        profiler.record_event(&make_event(
            "friend",
            "conv_1",
            EventKind::PhysicalThreat,
            (i + 2) * 1000,
        ));
    }
    let profile = profiler.profile("friend").unwrap();
    assert!(
        !profile.is_trusted,
        "10 high-severity threats should remove trusted flag"
    );
    assert!(
        profile.trust_level < 0.7,
        "Trust level should be below 0.7, got {}",
        profile.trust_level
    );
}

#[test]
fn propaganda_trust_decay_uses_half_rate() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "friend",
        "conv_1",
        EventKind::NormalConversation,
        1_000,
    ));
    profiler.mark_trusted("friend");

    profiler.record_event(&make_event(
        "friend",
        "conv_1",
        EventKind::SuspiciousSource,
        2_000,
    ));

    let profile = profiler.profile("friend").unwrap();
    let expected = 1.0 - EventKind::SuspiciousSource.severity() * 0.15 * 0.5;
    assert!(
        (profile.trust_level - expected).abs() < 1e-6,
        "Expected trust_level {}, got {}",
        expected,
        profile.trust_level
    );
}

#[test]
fn neutral_propaganda_context_does_not_accumulate_profile_risk() {
    let mut profiler = ContactProfiler::new();
    let mut event = make_event("friend", "conv_1", EventKind::PropagandaNarrative, 2_000);
    event.subtype = Some("war_denial".to_string());
    event.context.stance = EventStance::Neutral;
    event.context.confidence = 0.8;

    profiler.record_event(&event);

    let profile = profiler.profile("friend").unwrap();
    assert_eq!(profile.propaganda_event_count, 0);
    assert_eq!(profile.propaganda_score, 0.0);
    assert_eq!(profile.severity_count, 0);
    assert!(
        (profile.rating - 50.0).abs() < f32::EPSILON,
        "neutral context should not change rating, got {}",
        profile.rating
    );
}

#[test]
fn propaganda_weekly_counts_and_fingerprints_recorded() {
    let mut profiler = ContactProfiler::new();

    let mut event_a = make_event("agent", "conv_1", EventKind::PropagandaNarrative, 1_000);
    event_a.subtype = Some("war_denial".to_string());
    event_a.content_hash = Some(11);
    profiler.record_event(&event_a);

    let mut event_b = make_event("agent", "conv_1", EventKind::PropagandaNarrative, 2_000);
    event_b.subtype = Some("war_denial".to_string());
    event_b.content_hash = Some(11);
    profiler.record_event(&event_b);

    let mut event_c = make_event(
        "agent",
        "conv_1",
        EventKind::PropagandaNarrative,
        WEEK_MS + 3_000,
    );
    event_c.subtype = Some("capitulation".to_string());
    event_c.content_hash = Some(22);
    profiler.record_event(&event_c);

    let profile = profiler.profile("agent").unwrap();
    assert_eq!(profile.weekly_propaganda_counts.len(), 2);
    assert_eq!(profile.weekly_propaganda_counts[0].1, 2);
    assert_eq!(profile.weekly_propaganda_counts[1].1, 1);
    assert_eq!(profile.message_fingerprints.len(), 3);
    assert_eq!(profile.message_fingerprints[0], 11);
    assert_eq!(profile.message_fingerprints[1], 11);
    assert_eq!(profile.message_fingerprints[2], 22);
}

#[test]
fn propaganda_fingerprint_dedup_same_message_marker() {
    let mut profiler = ContactProfiler::new();

    let mut event_a = make_event("agent", "conv_1", EventKind::PropagandaNarrative, 10_000);
    event_a.subtype = Some("war_denial".to_string());
    event_a.content_hash = Some(999);
    profiler.record_event(&event_a);

    let mut event_b = make_event("agent", "conv_1", EventKind::SuspiciousSource, 10_000);
    event_b.content_hash = Some(999);
    profiler.record_event(&event_b);

    let profile = profiler.profile("agent").unwrap();
    let count = profile
        .message_fingerprints
        .iter()
        .filter(|&&fingerprint| fingerprint == 999)
        .count();
    assert_eq!(
        count, 1,
        "Same message marker should not duplicate fingerprint"
    );
}

#[test]
fn propaganda_weekly_counts_keep_chronological_order() {
    let mut profiler = ContactProfiler::new();

    let mut newer = make_event(
        "agent",
        "conv_1",
        EventKind::PropagandaNarrative,
        WEEK_MS + 1_000,
    );
    newer.subtype = Some("war_denial".to_string());
    profiler.record_event(&newer);

    let mut older = make_event("agent", "conv_1", EventKind::PropagandaNarrative, 1_000);
    older.subtype = Some("war_denial".to_string());
    profiler.record_event(&older);

    let profile = profiler.profile("agent").unwrap();
    assert_eq!(profile.weekly_propaganda_counts.len(), 2);
    assert!(
        profile.weekly_propaganda_counts[0].0 < profile.weekly_propaganda_counts[1].0,
        "Weekly propaganda buckets should stay chronological"
    );
}

#[test]
fn propaganda_score_recomputes_when_concentration_drops() {
    let mut profiler = ContactProfiler::new();

    for i in 0..10 {
        let mut event = make_event(
            "agent",
            "conv_1",
            EventKind::PropagandaNarrative,
            1_000 + i * 1_000,
        );
        event.subtype = Some("war_denial".to_string());
        event.content_hash = Some(500 + i);
        profiler.record_event(&event);
    }

    let score_before = profiler.profile("agent").unwrap().propaganda_score;

    for i in 0..30 {
        profiler.record_event(&make_event(
            "agent",
            "conv_1",
            EventKind::NormalConversation,
            50_000 + i * 1_000,
        ));
    }

    let score_after = profiler.profile("agent").unwrap().propaganda_score;
    assert!(
            score_after < score_before,
            "Expected propaganda score to drop after concentration decreases: before={score_before}, after={score_after}"
        );
}

#[test]
fn mark_trusted_sets_full_trust() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "uncle",
        "conv_1",
        EventKind::NormalConversation,
        1000,
    ));
    profiler.mark_trusted("uncle");
    let profile = profiler.profile("uncle").unwrap();
    assert_eq!(profile.trust_level, 1.0);
    assert!(profile.is_trusted);
}

#[test]
fn mark_trusted_creates_profile_before_first_message() {
    let mut profiler = ContactProfiler::new();
    profiler.mark_trusted("mom");

    let profile = profiler.profile("mom").unwrap();
    assert_eq!(profile.trust_level, 1.0);
    assert!(profile.is_trusted);
    assert!(!profiler.is_new_contact("mom"));
}

#[test]
fn circle_tier_new_under_14_days() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "newbie",
        "conv_1",
        EventKind::NormalConversation,
        1000,
    ));
    assert_eq!(
        profiler.profile("newbie").unwrap().circle_tier,
        CircleTier::New
    );
}

#[test]
fn circle_tier_inner_frequent() {
    let mut profiler = ContactProfiler::new();
    let start = 0u64;
    for day in 0..15 {
        for msg in 0..10 {
            profiler.record_event(&make_event(
                "bestie",
                "conv_1",
                EventKind::NormalConversation,
                start + day * DAY_MS + msg * 1000,
            ));
        }
    }
    assert_eq!(
        profiler.profile("bestie").unwrap().circle_tier,
        CircleTier::Inner
    );
}

#[test]
fn circle_tier_regular_weekly() {
    let mut profiler = ContactProfiler::new();
    for day in (0..30).step_by(2) {
        profiler.record_event(&make_event(
            "classmate",
            "conv_1",
            EventKind::NormalConversation,
            day * DAY_MS,
        ));
    }
    assert_eq!(
        profiler.profile("classmate").unwrap().circle_tier,
        CircleTier::Regular
    );
}

#[test]
fn circle_tier_occasional_rare() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "distant",
        "conv_1",
        EventKind::NormalConversation,
        0,
    ));
    profiler.record_event(&make_event(
        "distant",
        "conv_1",
        EventKind::NormalConversation,
        30 * DAY_MS,
    ));
    profiler.record_event(&make_event(
        "distant",
        "conv_1",
        EventKind::NormalConversation,
        60 * DAY_MS,
    ));
    assert_eq!(
        profiler.profile("distant").unwrap().circle_tier,
        CircleTier::Occasional
    );
}

#[test]
fn snapshot_created_on_first_event() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "alice",
        "conv_1",
        EventKind::NormalConversation,
        1000,
    ));
    let profile = profiler.profile("alice").unwrap();
    assert!(profile.current_snapshot.is_some());
    assert_eq!(profile.current_snapshot.as_ref().unwrap().total_messages, 1);
}

#[test]
fn snapshot_finalized_after_week() {
    let mut profiler = ContactProfiler::new();
    for i in 0..5 {
        profiler.record_event(&make_event(
            "alice",
            "conv_1",
            EventKind::NormalConversation,
            i * 1000,
        ));
    }
    assert_eq!(profiler.profile("alice").unwrap().weekly_snapshots.len(), 0);

    profiler.record_event(&make_event(
        "alice",
        "conv_1",
        EventKind::NormalConversation,
        WEEK_MS + 1000,
    ));
    assert_eq!(profiler.profile("alice").unwrap().weekly_snapshots.len(), 1);
    assert_eq!(
        profiler.profile("alice").unwrap().weekly_snapshots[0].total_messages,
        5
    );
}

#[test]
fn max_26_weekly_snapshots() {
    let mut profiler = ContactProfiler::new();
    for week in 0..30 {
        profiler.record_event(&make_event(
            "alice",
            "conv_1",
            EventKind::NormalConversation,
            week * WEEK_MS + 1000,
        ));
    }
    let profile = profiler.profile("alice").unwrap();
    assert!(
        profile.weekly_snapshots.len() <= MAX_SNAPSHOTS,
        "Should not exceed {} snapshots, got {}",
        MAX_SNAPSHOTS,
        profile.weekly_snapshots.len()
    );
}

#[test]
fn trend_stable_with_consistent_behavior() {
    let mut profiler = ContactProfiler::new();
    for week in 0..5 {
        for msg in 0..10 {
            profiler.record_event(&make_event(
                "stable",
                "conv_1",
                EventKind::NormalConversation,
                week * WEEK_MS + msg * 1000,
            ));
        }
    }
    profiler.record_event(&make_event(
        "stable",
        "conv_1",
        EventKind::NormalConversation,
        5 * WEEK_MS + 1000,
    ));
    assert_eq!(
        profiler.profile("stable").unwrap().trend,
        BehavioralTrend::Stable
    );
}

#[test]
fn trend_gradual_worsening_detected() {
    let mut profiler = ContactProfiler::new();
    for week in 0..3 {
        for msg in 0..10 {
            profiler.record_event(&make_event(
                "masha",
                "conv_1",
                EventKind::NormalConversation,
                week * WEEK_MS + msg * 1000,
            ));
        }
    }
    for week in 3..5 {
        for msg in 0..8 {
            profiler.record_event(&make_event(
                "masha",
                "conv_1",
                EventKind::NormalConversation,
                week * WEEK_MS + msg * 1000,
            ));
        }
        for msg in 8..10 {
            profiler.record_event(&make_event(
                "masha",
                "conv_1",
                EventKind::Insult,
                week * WEEK_MS + msg * 1000,
            ));
        }
    }
    profiler.record_event(&make_event(
        "masha",
        "conv_1",
        EventKind::Insult,
        5 * WEEK_MS + 1000,
    ));
    let trend = profiler.profile("masha").unwrap().trend;
    assert!(
        trend == BehavioralTrend::GradualWorsening || trend == BehavioralTrend::RapidWorsening,
        "Expected worsening trend, got {:?}",
        trend
    );
}

#[test]
fn trend_rapid_worsening_detected() {
    let mut profiler = ContactProfiler::new();
    for week in 0..3 {
        for msg in 0..10 {
            profiler.record_event(&make_event(
                "rapid",
                "conv_1",
                EventKind::NormalConversation,
                week * WEEK_MS + msg * 1000,
            ));
        }
    }
    for week in 3..5 {
        for msg in 0..6 {
            profiler.record_event(&make_event(
                "rapid",
                "conv_1",
                EventKind::NormalConversation,
                week * WEEK_MS + msg * 1000,
            ));
        }
        for msg in 6..10 {
            profiler.record_event(&make_event(
                "rapid",
                "conv_1",
                EventKind::Insult,
                week * WEEK_MS + msg * 1000,
            ));
        }
    }
    profiler.record_event(&make_event(
        "rapid",
        "conv_1",
        EventKind::Insult,
        5 * WEEK_MS + 1000,
    ));
    assert_eq!(
        profiler.profile("rapid").unwrap().trend,
        BehavioralTrend::RapidWorsening
    );
}

#[test]
fn trend_role_reversal_detected() {
    let mut profiler = ContactProfiler::new();
    for week in 0..3 {
        for msg in 0..6 {
            profiler.record_event(&make_event(
                "reversal",
                "conv_1",
                EventKind::NormalConversation,
                week * WEEK_MS + msg * 1000,
            ));
        }
        for msg in 6..10 {
            profiler.record_event(&make_event(
                "reversal",
                "conv_1",
                EventKind::DefenseOfVictim,
                week * WEEK_MS + msg * 1000,
            ));
        }
    }
    for week in 3..5 {
        for msg in 0..6 {
            profiler.record_event(&make_event(
                "reversal",
                "conv_1",
                EventKind::NormalConversation,
                week * WEEK_MS + msg * 1000,
            ));
        }
        for msg in 6..10 {
            profiler.record_event(&make_event(
                "reversal",
                "conv_1",
                EventKind::Insult,
                week * WEEK_MS + msg * 1000,
            ));
        }
    }
    profiler.record_event(&make_event(
        "reversal",
        "conv_1",
        EventKind::Insult,
        5 * WEEK_MS + 1000,
    ));
    assert_eq!(
        profiler.profile("reversal").unwrap().trend,
        BehavioralTrend::RoleReversal
    );
}

#[test]
fn shift_signal_generated_for_role_reversal() {
    let mut profiler = ContactProfiler::new();
    for week in 0..3 {
        for msg in 0..6 {
            profiler.record_event(&make_event(
                "turner",
                "conv_1",
                EventKind::NormalConversation,
                week * WEEK_MS + msg * 1000,
            ));
        }
        for msg in 6..10 {
            profiler.record_event(&make_event(
                "turner",
                "conv_1",
                EventKind::DefenseOfVictim,
                week * WEEK_MS + msg * 1000,
            ));
        }
    }
    for week in 3..5 {
        for msg in 0..6 {
            profiler.record_event(&make_event(
                "turner",
                "conv_1",
                EventKind::NormalConversation,
                week * WEEK_MS + msg * 1000,
            ));
        }
        for msg in 6..10 {
            profiler.record_event(&make_event(
                "turner",
                "conv_1",
                EventKind::Insult,
                week * WEEK_MS + msg * 1000,
            ));
        }
    }
    profiler.record_event(&make_event(
        "turner",
        "conv_1",
        EventKind::Insult,
        5 * WEEK_MS + 1000,
    ));

    let signals = profiler.check_behavioral_shift("turner");
    assert!(
        !signals.is_empty(),
        "Role reversal should generate a behavioral shift signal"
    );
    assert_eq!(signals[0].threat_type, ThreatType::Bullying);
    assert!(signals[0].score >= 0.6);
}

#[test]
fn shift_signal_boosted_for_inner_circle() {
    let mut profiler = ContactProfiler::new();
    for day in 0..15 {
        for msg in 0..10 {
            let week = day / 7;
            let ts = day as u64 * DAY_MS + msg * 1000;
            let kind = if week < 2 {
                if msg < 6 {
                    EventKind::NormalConversation
                } else {
                    EventKind::DefenseOfVictim
                }
            } else {
                EventKind::NormalConversation
            };
            profiler.record_event(&make_event("inner_friend", "conv_1", kind, ts));
        }
    }
    for day in 21..35 {
        for msg in 0..10 {
            let ts = day as u64 * DAY_MS + msg * 1000;
            let kind = if msg < 6 {
                EventKind::NormalConversation
            } else {
                EventKind::Insult
            };
            profiler.record_event(&make_event("inner_friend", "conv_1", kind, ts));
        }
    }
    profiler.record_event(&make_event(
        "inner_friend",
        "conv_1",
        EventKind::Insult,
        35 * DAY_MS + 1000,
    ));

    let profile = profiler.profile("inner_friend").unwrap();
    assert_eq!(profile.circle_tier, CircleTier::Inner);

    let signals = profiler.check_behavioral_shift("inner_friend");
    if !signals.is_empty() {
        assert!(
            signals[0].score >= 0.45,
            "Inner circle should boost signal score, got {}",
            signals[0].score
        );
    }
}

#[test]
fn incomplete_old_state_deserialization_is_rejected() {
    let old_json = r#"{"profiles":[{
            "sender_id":"alice",
            "first_seen_ms":1000,
            "last_seen_ms":2000,
            "total_messages":5,
            "conversation_count":1,
            "conversations":["conv_1"],
            "grooming_event_count":0,
            "bullying_event_count":0,
            "manipulation_event_count":0,
            "is_trusted":true,
            "severity_sum":0.0,
            "severity_count":0
        }]}"#;
    let state: Result<ContactProfilerState, _> = serde_json::from_str(old_json);
    assert!(state.is_err(), "incomplete state should not deserialize");
}

#[test]
fn scenario_friend_to_bully_over_3_months() {
    let mut profiler = ContactProfiler::new();
    let week = WEEK_MS;

    for w in 0..4 {
        for msg in 0..10 {
            profiler.record_event(&make_event(
                "masha",
                "conv_1",
                EventKind::NormalConversation,
                w * week + msg * 1000,
            ));
        }
    }
    let sept_rating = profiler.profile("masha").unwrap().rating;
    assert!(
        sept_rating > 50.0,
        "September: rating should be above 50, got {sept_rating}"
    );

    for w in 4..8 {
        for msg in 0..8 {
            profiler.record_event(&make_event(
                "masha",
                "conv_1",
                EventKind::NormalConversation,
                w * week + msg * 1000,
            ));
        }
        for msg in 8..10 {
            profiler.record_event(&make_event(
                "masha",
                "conv_1",
                EventKind::Insult,
                w * week + msg * 1000,
            ));
        }
    }
    let oct_rating = profiler.profile("masha").unwrap().rating;
    assert!(
        oct_rating < sept_rating,
        "October: rating should decrease: sept={sept_rating} oct={oct_rating}"
    );

    for w in 8..16 {
        for msg in 0..4 {
            profiler.record_event(&make_event(
                "masha",
                "conv_1",
                EventKind::NormalConversation,
                w * week + msg * 1000,
            ));
        }
        for msg in 4..10 {
            profiler.record_event(&make_event(
                "masha",
                "conv_1",
                EventKind::Insult,
                w * week + msg * 1000,
            ));
        }
    }
    profiler.record_event(&make_event(
        "masha",
        "conv_1",
        EventKind::Insult,
        16 * week + 1000,
    ));

    let profile = profiler.profile("masha").unwrap();
    assert!(
        profile.rating < 30.0,
        "December: rating should be very low, got {}",
        profile.rating
    );
    assert!(
        profile.trend == BehavioralTrend::RapidWorsening
            || profile.trend == BehavioralTrend::GradualWorsening,
        "Should detect worsening trend, got {:?}",
        profile.trend
    );

    let signals = profiler.check_behavioral_shift("masha");
    assert!(
        !signals.is_empty(),
        "Should generate shift signal for friend-to-bully"
    );
}

#[test]
fn scenario_trusted_adult_starts_grooming() {
    let mut profiler = ContactProfiler::new();
    for w in 0..4 {
        for msg in 0..10 {
            profiler.record_event(&make_event(
                "coach",
                "conv_1",
                EventKind::NormalConversation,
                w * WEEK_MS + msg * 1000,
            ));
        }
    }
    profiler.mark_trusted("coach");
    assert_eq!(profiler.profile("coach").unwrap().trust_level, 1.0);

    let baseline_rating = profiler.profile("coach").unwrap().rating;

    for w in 4..8 {
        for msg in 0..5 {
            profiler.record_event(&make_event(
                "coach",
                "conv_1",
                EventKind::NormalConversation,
                w * WEEK_MS + msg * 1000,
            ));
        }
        profiler.record_event(&make_event(
            "coach",
            "conv_1",
            EventKind::Flattery,
            w * WEEK_MS + 5000,
        ));
        profiler.record_event(&make_event(
            "coach",
            "conv_1",
            EventKind::PersonalInfoRequest,
            w * WEEK_MS + 6000,
        ));
        profiler.record_event(&make_event(
            "coach",
            "conv_1",
            EventKind::GiftOffer,
            w * WEEK_MS + 7000,
        ));
    }

    let profile = profiler.profile("coach").unwrap();
    assert!(
        profile.rating < baseline_rating,
        "Rating should decrease from grooming: baseline={baseline_rating} now={}",
        profile.rating
    );
    assert!(
        profile.trust_level < 0.7,
        "Repeated live grooming should revoke inherited trust: {}",
        profile.trust_level
    );
    assert!(!profile.is_trusted);
}

#[test]
fn scenario_trusted_adult_escalates_to_hostile() {
    let mut profiler = ContactProfiler::new();

    for w in 0..3 {
        for msg in 0..10 {
            profiler.record_event(&make_event(
                "teacher",
                "conv_1",
                EventKind::NormalConversation,
                w * WEEK_MS + msg * 1000,
            ));
        }
    }
    profiler.mark_trusted("teacher");

    for w in 3..6 {
        for msg in 0..5 {
            profiler.record_event(&make_event(
                "teacher",
                "conv_1",
                EventKind::Gaslighting,
                w * WEEK_MS + msg * 1000,
            ));
        }
        for msg in 5..10 {
            profiler.record_event(&make_event(
                "teacher",
                "conv_1",
                EventKind::EmotionalBlackmail,
                w * WEEK_MS + msg * 1000,
            ));
        }
    }
    profiler.record_event(&make_event(
        "teacher",
        "conv_1",
        EventKind::Gaslighting,
        6 * WEEK_MS + 1000,
    ));

    let profile = profiler.profile("teacher").unwrap();
    assert!(
        profile.trust_level < 0.3,
        "Trust should be destroyed after sustained hostility: {}",
        profile.trust_level
    );
    assert!(!profile.is_trusted, "Should no longer be trusted");
    assert!(
        profile.rating < 20.0,
        "Rating should be very low: {}",
        profile.rating
    );
}

#[test]
fn scenario_recovery_after_hostility() {
    let mut profiler = ContactProfiler::new();

    for w in 0..3 {
        for msg in 0..10 {
            profiler.record_event(&make_event(
                "recovering",
                "conv_1",
                EventKind::Insult,
                w * WEEK_MS + msg * 1000,
            ));
        }
    }
    let hostile_rating = profiler.profile("recovering").unwrap().rating;

    for w in 3..8 {
        for msg in 0..10 {
            profiler.record_event(&make_event(
                "recovering",
                "conv_1",
                EventKind::NormalConversation,
                w * WEEK_MS + msg * 1000,
            ));
        }
    }
    profiler.record_event(&make_event(
        "recovering",
        "conv_1",
        EventKind::NormalConversation,
        8 * WEEK_MS + 1000,
    ));

    let profile = profiler.profile("recovering").unwrap();
    assert!(
        profile.rating > hostile_rating,
        "Rating should improve during recovery: hostile={hostile_rating} now={}",
        profile.rating
    );
    assert!(
        profile.trend == BehavioralTrend::Improving || profile.trend == BehavioralTrend::Stable,
        "Trend should show improvement or stability, got {:?}",
        profile.trend
    );
}

#[test]
fn scenario_mixed_signals_alternating_weeks() {
    let mut profiler = ContactProfiler::new();

    for w in 0..8u64 {
        if w % 2 == 0 {
            for msg in 0..10 {
                profiler.record_event(&make_event(
                    "mixed",
                    "conv_1",
                    EventKind::NormalConversation,
                    w * WEEK_MS + msg * 1000,
                ));
            }
        } else {
            for msg in 0..4 {
                profiler.record_event(&make_event(
                    "mixed",
                    "conv_1",
                    EventKind::NormalConversation,
                    w * WEEK_MS + msg * 1000,
                ));
            }
            for msg in 4..10 {
                profiler.record_event(&make_event(
                    "mixed",
                    "conv_1",
                    EventKind::Insult,
                    w * WEEK_MS + msg * 1000,
                ));
            }
        }
    }
    profiler.record_event(&make_event(
        "mixed",
        "conv_1",
        EventKind::NormalConversation,
        8 * WEEK_MS + 1000,
    ));

    let profile = profiler.profile("mixed").unwrap();
    assert!(
        profile.rating < 60.0,
        "Mixed signals should give moderate-to-low rating, got {}",
        profile.rating
    );
}

#[test]
fn scenario_new_contact_rapid_grooming() {
    let mut profiler = ContactProfiler::new();

    profiler.record_event(&make_event("stranger", "conv_1", EventKind::Flattery, 0));
    profiler.record_event(&make_event("stranger", "conv_1", EventKind::Flattery, 1000));

    profiler.record_event(&make_event(
        "stranger",
        "conv_1",
        EventKind::GiftOffer,
        DAY_MS,
    ));
    profiler.record_event(&make_event(
        "stranger",
        "conv_1",
        EventKind::PersonalInfoRequest,
        DAY_MS + 1000,
    ));

    profiler.record_event(&make_event(
        "stranger",
        "conv_1",
        EventKind::SecrecyRequest,
        2 * DAY_MS,
    ));
    profiler.record_event(&make_event(
        "stranger",
        "conv_1",
        EventKind::PlatformSwitch,
        2 * DAY_MS + 1000,
    ));

    profiler.record_event(&make_event(
        "stranger",
        "conv_1",
        EventKind::PhotoRequest,
        4 * DAY_MS,
    ));
    profiler.record_event(&make_event(
        "stranger",
        "conv_1",
        EventKind::MeetingRequest,
        4 * DAY_MS + 1000,
    ));

    let profile = profiler.profile("stranger").unwrap();
    assert_eq!(
        profile.circle_tier,
        CircleTier::New,
        "Should still be New (<14 days)"
    );
    assert!(
        profile.rating < 45.0,
        "Rating should drop from grooming: {}",
        profile.rating
    );
    assert!(profile.grooming_event_count >= 8);
}

#[test]
fn scenario_normal_teen_drama_no_false_positive() {
    let mut profiler = ContactProfiler::new();

    for msg in 0..9 {
        profiler.record_event(&make_event(
            "classmate",
            "conv_1",
            EventKind::NormalConversation,
            msg * 1000,
        ));
    }
    profiler.record_event(&make_event(
        "classmate",
        "conv_1",
        EventKind::Insult,
        9 * 1000,
    ));

    for w in 1..5 {
        for msg in 0..10 {
            profiler.record_event(&make_event(
                "classmate",
                "conv_1",
                EventKind::NormalConversation,
                w * WEEK_MS + msg * 1000,
            ));
        }
    }
    profiler.record_event(&make_event(
        "classmate",
        "conv_1",
        EventKind::NormalConversation,
        5 * WEEK_MS + 1000,
    ));

    let profile = profiler.profile("classmate").unwrap();
    assert!(
        profile.rating > 40.0,
        "Normal teen drama should not tank rating: {}",
        profile.rating
    );
    assert!(
        profile.trend == BehavioralTrend::Stable || profile.trend == BehavioralTrend::Improving,
        "Trend should be stable/improving after reconciliation: {:?}",
        profile.trend
    );

    let signals = profiler.check_behavioral_shift("classmate");
    assert!(
        signals.is_empty(),
        "No behavioral shift signal for normal teen drama"
    );
}

#[test]
fn rating_floor_after_sustained_attack() {
    let mut profiler = ContactProfiler::new();
    for i in 0..50 {
        profiler.record_event(&make_event(
            "attacker",
            "conv_1",
            EventKind::PhysicalThreat,
            i * 1000,
        ));
    }
    let profile = profiler.profile("attacker").unwrap();
    assert_eq!(profile.rating, 0.0, "Rating should floor at 0");
}

#[test]
fn rating_ceiling_from_supportive() {
    let mut profiler = ContactProfiler::new();
    for i in 0..100 {
        profiler.record_event(&make_event(
            "hero",
            "conv_1",
            EventKind::DefenseOfVictim,
            i * 1000,
        ));
    }
    let profile = profiler.profile("hero").unwrap();
    assert_eq!(profile.rating, 100.0, "Rating should cap at 100");
}

#[test]
fn trust_zero_floor() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "person",
        "conv_1",
        EventKind::NormalConversation,
        0,
    ));
    profiler.mark_trusted("person");

    for i in 0..50 {
        profiler.record_event(&make_event(
            "person",
            "conv_1",
            EventKind::HarmEncouragement,
            (i + 1) * 1000,
        ));
    }
    let profile = profiler.profile("person").unwrap();
    assert_eq!(profile.trust_level, 0.0, "Trust should floor at 0.0");
}

#[test]
fn snapshot_at_exact_week_boundary() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "alice",
        "conv_1",
        EventKind::NormalConversation,
        0,
    ));
    profiler.record_event(&make_event(
        "alice",
        "conv_1",
        EventKind::NormalConversation,
        WEEK_MS,
    ));
    assert_eq!(profiler.profile("alice").unwrap().weekly_snapshots.len(), 1);
}

#[test]
fn circle_tier_exactly_14_days() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "exact",
        "conv_1",
        EventKind::NormalConversation,
        0,
    ));
    profiler.record_event(&make_event(
        "exact",
        "conv_1",
        EventKind::NormalConversation,
        14 * DAY_MS,
    ));
    assert_ne!(
        profiler.profile("exact").unwrap().circle_tier,
        CircleTier::New,
        "At exactly 14 days should exit New tier"
    );
}

#[test]
fn multiple_conversations_same_contact() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "multi",
        "conv_1",
        EventKind::NormalConversation,
        0,
    ));
    profiler.record_event(&make_event("multi", "conv_2", EventKind::Insult, 1000));
    profiler.record_event(&make_event("multi", "conv_3", EventKind::Flattery, 2000));

    let profile = profiler.profile("multi").unwrap();
    assert_eq!(profile.conversation_count, 3);
    assert_eq!(profile.total_messages, 3);
}

#[test]
fn cleanup_preserves_recent_active_days() {
    let mut profiler = ContactProfiler::new();

    for day in 0..200u64 {
        profiler.record_event(&make_event(
            "longterm",
            "conv_1",
            EventKind::NormalConversation,
            day * DAY_MS,
        ));
    }

    let before = profiler.profile("longterm").unwrap().active_days.len();

    profiler.cleanup(150 * DAY_MS);

    let profile = profiler.profile("longterm").unwrap();
    assert!(
        profile.active_days.len() < before,
        "Cleanup should prune old active_days: before={before} after={}",
        profile.active_days.len()
    );
    assert!(
        !profile.active_days.is_empty(),
        "Should keep recent active_days"
    );
}

#[test]
fn export_import_preserves_rating_and_snapshots() {
    let mut profiler = ContactProfiler::new();

    for w in 0..4 {
        for msg in 0..5 {
            profiler.record_event(&make_event(
                "alice",
                "conv_1",
                EventKind::NormalConversation,
                w * WEEK_MS + msg * 1000,
            ));
        }
    }
    profiler.record_event(&make_event(
        "alice",
        "conv_1",
        EventKind::Insult,
        4 * WEEK_MS,
    ));

    let state = profiler.export();
    let orig_profile = profiler.profile("alice").unwrap();
    let orig_rating = orig_profile.rating;
    let orig_snapshots = orig_profile.weekly_snapshots.len();

    let mut profiler2 = ContactProfiler::new();
    profiler2.import(state);

    let imported = profiler2.profile("alice").unwrap();
    assert_eq!(
        imported.rating, orig_rating,
        "Rating should survive export/import"
    );
    assert_eq!(
        imported.weekly_snapshots.len(),
        orig_snapshots,
        "Snapshots should survive export/import"
    );
}

#[test]
fn no_behavioral_shift_for_new_contacts() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event("newbie", "conv_1", EventKind::Insult, 0));
    profiler.record_event(&make_event("newbie", "conv_1", EventKind::Insult, 1000));

    let signals = profiler.check_behavioral_shift("newbie");
    assert!(
        signals.is_empty(),
        "New contacts without 3+ snapshots should not generate shift signals"
    );
}

#[test]
fn no_behavioral_shift_for_unknown_contact() {
    let profiler = ContactProfiler::new();
    let signals = profiler.check_behavioral_shift("nonexistent");
    assert!(
        signals.is_empty(),
        "Unknown contact should return empty signals"
    );
}

#[test]
fn low_rating_inner_circle_alert() {
    let mut profiler = ContactProfiler::new();

    for day in 0..30u64 {
        for msg in 0..10 {
            let kind = if day < 5 {
                EventKind::NormalConversation
            } else {
                EventKind::PhysicalThreat
            };
            profiler.record_event(&make_event(
                "inner_bully",
                "conv_1",
                kind,
                day * DAY_MS + msg * 1000,
            ));
        }
    }

    profiler.record_event(&make_event(
        "inner_bully",
        "conv_1",
        EventKind::PhysicalThreat,
        30 * DAY_MS + 1000,
    ));
    let profile = profiler.profile("inner_bully").unwrap();
    assert_eq!(profile.circle_tier, CircleTier::Inner);

    let signals = profiler.check_behavioral_shift("inner_bully");
    let has_low_rating = signals
        .iter()
        .any(|s| s.explanation.contains("critically low rating"));
    if profile.rating < 20.0 {
        assert!(
            has_low_rating,
            "Inner circle with low rating should trigger alert"
        );
    }
}

#[test]
fn graduated_trust_discount_in_risk_score() {
    let mut profiler = ContactProfiler::new();

    for i in 0..5 {
        profiler.record_event(&make_event(
            "untrusted",
            "conv_1",
            EventKind::Flattery,
            i * 1000,
        ));
        profiler.record_event(&make_event(
            "trusted",
            "conv_2",
            EventKind::Flattery,
            i * 1000,
        ));
    }
    profiler.mark_trusted("trusted");

    let untrusted_risk = profiler.profile("untrusted").unwrap().risk_score();
    let trusted_risk = profiler.profile("trusted").unwrap().risk_score();

    assert!(
        trusted_risk < untrusted_risk,
        "Trusted contact should have lower risk: trusted={trusted_risk} untrusted={untrusted_risk}"
    );
}

#[test]
fn property_rating_always_in_0_100() {
    let mut profiler = ContactProfiler::new();
    let all_kinds = all_event_kinds();
    for (i, kind) in all_kinds.iter().enumerate() {
        profiler.record_event(&make_event("prop", "conv", kind.clone(), i as u64 * 1000));
        let r = profiler.profile("prop").unwrap().rating;
        assert!(
            (0.0..=100.0).contains(&r),
            "{kind:?} at step {i} produced rating {r}"
        );
    }
}

#[test]
fn property_trust_always_in_0_1() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event("t", "c", EventKind::NormalConversation, 0));
    profiler.mark_trusted("t");
    let all_kinds = all_event_kinds();
    for (i, kind) in all_kinds.iter().enumerate() {
        profiler.record_event(&make_event("t", "c", kind.clone(), (i + 1) as u64 * 1000));
        let t = profiler.profile("t").unwrap().trust_level;
        assert!(
            (0.0..=1.0).contains(&t),
            "{kind:?} at step {i} produced trust {t}"
        );
    }
}

#[test]
fn property_risk_score_always_in_0_1() {
    let mut profiler = ContactProfiler::new();
    let all_kinds = all_event_kinds();
    for (i, kind) in all_kinds.iter().enumerate() {
        profiler.record_event(&make_event("r", "c", kind.clone(), i as u64 * 1000));
        let r = profiler.profile("r").unwrap().risk_score();
        assert!(
            (0.0..=1.0).contains(&r),
            "{kind:?} at step {i} produced risk_score {r}"
        );
    }
}

#[test]
fn property_snapshot_counters_consistent() {
    let mut profiler = ContactProfiler::new();
    let all_kinds = all_event_kinds();
    for (i, kind) in all_kinds.iter().enumerate() {
        profiler.record_event(&make_event("s", "c", kind.clone(), i as u64 * 1000));
    }
    let profile = profiler.profile("s").unwrap();
    if let Some(snap) = &profile.current_snapshot {
        let sum = snap.hostile_count + snap.supportive_count + snap.neutral_count;
        assert_eq!(
            sum, snap.total_messages,
            "hostile({}) + supportive({}) + neutral({}) != total({})",
            snap.hostile_count, snap.supportive_count, snap.neutral_count, snap.total_messages
        );
    }
}

#[test]
fn property_rating_monotonic_under_pure_hostile() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event("m", "c", EventKind::NormalConversation, 0));
    let mut prev_rating = profiler.profile("m").unwrap().rating;
    let hostile_kinds = vec![
        EventKind::Insult,
        EventKind::PhysicalThreat,
        EventKind::HarmEncouragement,
        EventKind::Gaslighting,
        EventKind::EmotionalBlackmail,
        EventKind::Denigration,
        EventKind::Mockery,
        EventKind::DoxxingAttempt,
        EventKind::HateSpeech,
    ];
    for (i, kind) in hostile_kinds.iter().enumerate() {
        profiler.record_event(&make_event("m", "c", kind.clone(), (i + 1) as u64 * 1000));
        let r = profiler.profile("m").unwrap().rating;
        assert!(
            r <= prev_rating,
            "Rating increased from {prev_rating} to {r} after {kind:?}"
        );
        prev_rating = r;
    }
}

#[test]
fn property_trust_monotonic_under_hostile() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event("t", "c", EventKind::NormalConversation, 0));
    profiler.mark_trusted("t");
    let mut prev_trust = 1.0;
    for i in 0..20 {
        profiler.record_event(&make_event("t", "c", EventKind::Insult, (i + 1) * 1000));
        let t = profiler.profile("t").unwrap().trust_level;
        assert!(
            t <= prev_trust,
            "Trust increased from {prev_trust} to {t} at step {i}"
        );
        prev_trust = t;
    }
}

#[test]
fn property_all_event_kinds_have_valid_severity() {
    let all_kinds = all_event_kinds();
    for kind in &all_kinds {
        let s = kind.severity();
        assert!(
            (0.0..=1.0).contains(&s),
            "{kind:?} has invalid severity {s}"
        );
    }
}

#[test]
fn property_hostile_events_always_negative_delta() {
    let all_kinds = all_event_kinds();
    for kind in &all_kinds {
        if kind.is_hostile() {
            assert!(
                kind.rating_delta() < 0.0,
                "Hostile {kind:?} has non-negative delta {}",
                kind.rating_delta()
            );
        }
    }
}

#[test]
fn property_supportive_events_always_positive_delta() {
    let all_kinds = all_event_kinds();
    for kind in &all_kinds {
        if kind.is_supportive() {
            assert!(
                kind.rating_delta() > 0.0,
                "Supportive {kind:?} has non-positive delta {}",
                kind.rating_delta()
            );
        }
    }
}

#[test]
fn fuzz_max_timestamp() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "x",
        "c",
        EventKind::NormalConversation,
        u64::MAX,
    ));
    let p = profiler.profile("x").unwrap();
    assert!(p.rating >= 0.0);
}

#[test]
fn fuzz_zero_timestamp() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event("x", "c", EventKind::NormalConversation, 0));
    assert!(profiler.profile("x").is_some());
}

#[test]
fn fuzz_empty_sender_id() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event("", "c", EventKind::NormalConversation, 1000));
    assert!(profiler.profile("").is_some());
}

#[test]
fn fuzz_empty_conversation_id() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event("x", "", EventKind::NormalConversation, 1000));
    let p = profiler.profile("x").unwrap();
    assert_eq!(p.conversation_count, 1);
}

#[test]
fn fuzz_unicode_sender_id() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "\u{1f9d2}\u{1f466}",
        "c",
        EventKind::Insult,
        1000,
    ));
    assert!(profiler.profile("\u{1f9d2}\u{1f466}").is_some());
}

#[test]
fn fuzz_extremely_long_sender_id() {
    let mut profiler = ContactProfiler::new();
    let long_id = "a".repeat(10_000);
    profiler.record_event(&make_event(
        &long_id,
        "c",
        EventKind::NormalConversation,
        1000,
    ));
    assert!(profiler.profile(&long_id).is_some());
}

#[test]
fn fuzz_timestamp_backwards() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event("x", "c", EventKind::NormalConversation, 10000));
    profiler.record_event(&make_event("x", "c", EventKind::Insult, 5000));
    let p = profiler.profile("x").unwrap();
    assert_eq!(p.last_seen_ms, 10000);
}

#[test]
fn fuzz_same_timestamp_many_events() {
    let mut profiler = ContactProfiler::new();
    for _ in 0..100 {
        profiler.record_event(&make_event("x", "c", EventKind::NormalConversation, 42));
    }
    let p = profiler.profile("x").unwrap();
    assert_eq!(p.total_messages, 100);
    assert!(p.rating >= 0.0 && p.rating <= 100.0);
}

#[test]
fn fuzz_rapid_trust_swing() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event("sw", "c", EventKind::NormalConversation, 0));

    for cycle in 0..5u64 {
        profiler.mark_trusted("sw");
        assert_eq!(profiler.profile("sw").unwrap().trust_level, 1.0);
        for i in 0..20 {
            profiler.record_event(&make_event(
                "sw",
                "c",
                EventKind::PhysicalThreat,
                cycle * 100000 + (i + 1) * 1000,
            ));
        }
        let t = profiler.profile("sw").unwrap().trust_level;
        assert!(
            (0.0..=1.0).contains(&t),
            "Trust out of range after cycle {cycle}: {t}"
        );
    }
}

#[test]
fn fuzz_cleanup_with_zero_cutoff() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event("x", "c", EventKind::NormalConversation, 1000));
    profiler.cleanup(0);
    assert!(profiler.profile("x").is_some());
}

#[test]
fn fuzz_cleanup_with_max_cutoff() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event("x", "c", EventKind::NormalConversation, 1000));
    profiler.cleanup(u64::MAX);
    assert!(profiler.profile("x").is_none());
}

#[test]
fn fuzz_export_import_empty_profiler() {
    let profiler = ContactProfiler::new();
    let state = profiler.export();
    assert!(state.profiles.is_empty());
    let mut profiler2 = ContactProfiler::new();
    profiler2.import(state);
}

#[test]
fn max_profile_limit_evicts_oldest_sender() {
    let mut profiler = ContactProfiler::with_max_profiles(2);
    profiler.record_event(&make_event(
        "oldest",
        "c1",
        EventKind::NormalConversation,
        1_000,
    ));
    profiler.record_event(&make_event(
        "middle",
        "c2",
        EventKind::NormalConversation,
        2_000,
    ));
    profiler.record_event(&make_event(
        "newest",
        "c3",
        EventKind::NormalConversation,
        3_000,
    ));

    assert!(profiler.profile("oldest").is_none());
    assert!(profiler.profile("middle").is_some());
    assert!(profiler.profile("newest").is_some());
}

#[test]
fn max_profile_limit_prefers_keeping_higher_risk_contact() {
    let mut profiler = ContactProfiler::with_max_profiles(2);
    // Build enough grooming events to push risky_old into risk band ≥1
    // (risk_score ≥ 0.45). Each grooming event adds 0.1, capped at 0.4.
    // Five events → 0.4 grooming + severity bonus → exceeds 0.45.
    for ts in 0..5 {
        profiler.record_event(&make_event(
            "risky_old",
            "c1",
            EventKind::SecrecyRequest,
            1_000 + ts * 100,
        ));
    }
    profiler.record_event(&make_event(
        "benign_newer",
        "c2",
        EventKind::NormalConversation,
        2_000,
    ));
    profiler.record_event(&make_event(
        "incoming",
        "c3",
        EventKind::NormalConversation,
        3_000,
    ));

    assert!(profiler.profile("risky_old").is_some());
    assert!(profiler.profile("incoming").is_some());
    assert!(profiler.profile("benign_newer").is_none());
}

#[test]
fn import_respects_profile_limit() {
    let mut profiler = ContactProfiler::with_max_profiles(2);
    profiler.import(ContactProfilerState {
        profiles: vec![
            ContactProfile::new("alice".into(), 1_000),
            ContactProfile::new("bob".into(), 2_000),
            ContactProfile::new("carol".into(), 3_000),
        ],
    });

    assert!(profiler.profile("alice").is_none());
    assert!(profiler.profile("bob").is_some());
    assert!(profiler.profile("carol").is_some());
}

#[test]
fn fuzz_deserialize_corrupt_rating() {
    let json = r#"{"profiles":[{
            "sender_id":"x","first_seen_ms":0,"last_seen_ms":1000,"total_messages":1,
            "conversation_count":1,"conversations":["c"],"grooming_event_count":0,
            "bullying_event_count":0,"manipulation_event_count":0,
            "propaganda_event_count":0,"propaganda_source_count":0,"narrative_hits":[],
            "propaganda_score":0.0,"narrative_diversity":0,"first_propaganda_ms":0,
            "last_propaganda_ms":0,"propaganda_conversations":[],"hourly_activity":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "message_fingerprints":[],"narrative_timeline":[],"weekly_propaganda_counts":[],
            "is_trusted":false,"severity_sum":0.0,"severity_count":0,
            "rating":999.0,"trust_level":5.0,"inferred_age":null,"age_source":"user_reported",
            "circle_tier":"new","trend":"stable","weekly_snapshots":[],"current_snapshot":null,
            "active_days":[]
        }]}"#;
    let state: ContactProfilerState = serde_json::from_str(json).unwrap();
    let mut profiler = ContactProfiler::new();
    profiler.import(state);
    let p = profiler.profile("x").unwrap();
    assert_eq!(p.rating, 999.0);
}

#[test]
fn wire_state_roundtrip_preserves_age_source() {
    let mut profiler = ContactProfiler::new();
    profiler.record_event(&make_event(
        "alice",
        "conv_1",
        EventKind::NormalConversation,
        1_000,
    ));
    {
        let profile = profiler.profiles.get_mut("alice").unwrap();
        profile.inferred_age = Some(17);
        profile.age_source = AgeSource::MlInferred;
    }

    let wire = profiler.export_wire_state();
    let mut restored = ContactProfiler::new();
    restored.import_wire_state(wire);

    let restored_profile = restored.profile("alice").unwrap();
    assert_eq!(restored_profile.inferred_age, Some(17));
    assert_eq!(restored_profile.age_source, AgeSource::MlInferred);
}

#[test]
fn stress_1000_contacts_52_weeks() {
    let mut profiler = ContactProfiler::new();
    let week = WEEK_MS;

    for contact in 0..1000u64 {
        let sender = format!("contact_{contact}");
        for w in 0..52 {
            for msg in 0..5 {
                let kind = if contact % 10 == 0 && w > 40 {
                    EventKind::Insult
                } else {
                    EventKind::NormalConversation
                };
                profiler.record_event(&make_event(
                    &sender,
                    "conv_1",
                    kind,
                    w * week + msg * 1000 + contact,
                ));
            }
        }
    }

    for i in 0..1000u64 {
        let sender = format!("contact_{i}");
        let p = profiler.profile(&sender).unwrap();
        assert_eq!(
            p.total_messages, 260,
            "contact_{i} should have 260 messages"
        );
        assert!((0.0..=100.0).contains(&p.rating));
        assert!((0.0..=1.0).contains(&p.trust_level));
    }

    let hostile_contact = profiler.profile("contact_0").unwrap();
    let normal_contact = profiler.profile("contact_1").unwrap();
    assert!(
        hostile_contact.rating < normal_contact.rating,
        "Hostile contact rating {} should be lower than normal {}",
        hostile_contact.rating,
        normal_contact.rating
    );

    for i in 0..1000u64 {
        let sender = format!("contact_{i}");
        let p = profiler.profile(&sender).unwrap();
        assert!(
            p.weekly_snapshots().len() <= MAX_SNAPSHOTS,
            "contact_{i} has {} snapshots, max is {MAX_SNAPSHOTS}",
            p.weekly_snapshots().len()
        );
    }
}

#[test]
fn stress_sort_1000_contacts_by_risk() {
    let mut profiler = ContactProfiler::new();

    for i in 0..1000u64 {
        let sender = format!("user_{i}");
        for j in 0..(i % 10) {
            profiler.record_event(&make_event(
                &sender,
                "conv_1",
                EventKind::Flattery,
                j * 1000,
            ));
        }
        profiler.record_event(&make_event(
            &sender,
            "conv_1",
            EventKind::NormalConversation,
            10000,
        ));
    }

    let sorted = profiler.contacts_by_risk();
    assert_eq!(sorted.len(), 1000);

    for window in sorted.windows(2) {
        assert!(
            window[0].risk_score() >= window[1].risk_score(),
            "Not sorted: {} has risk {} but {} has risk {}",
            window[0].sender_id,
            window[0].risk_score(),
            window[1].sender_id,
            window[1].risk_score()
        );
    }
}

#[test]
fn stress_10000_events_single_contact() {
    let mut profiler = ContactProfiler::new();

    for i in 0..10_000u64 {
        let kind = match i % 5 {
            0 => EventKind::NormalConversation,
            1 => EventKind::Insult,
            2 => EventKind::DefenseOfVictim,
            3 => EventKind::Flattery,
            _ => EventKind::NormalConversation,
        };
        profiler.record_event(&make_event("heavy", "conv_1", kind, i * 1000));
    }

    let p = profiler.profile("heavy").unwrap();
    assert_eq!(p.total_messages, 10_000);
    assert!((0.0..=100.0).contains(&p.rating));
    assert!((0.0..=1.0).contains(&p.trust_level));
    assert_eq!(p.weekly_snapshots().len(), 0, "All events within one week");
}

#[test]
fn skipped_weeks_3_week_gap_then_return() {
    let mut profiler = ContactProfiler::new();

    for msg in 0..10 {
        profiler.record_event(&make_event(
            "gap",
            "conv_1",
            EventKind::NormalConversation,
            msg * 1000,
        ));
    }

    for msg in 0..10 {
        profiler.record_event(&make_event(
            "gap",
            "conv_1",
            EventKind::NormalConversation,
            4 * WEEK_MS + msg * 1000,
        ));
    }

    let p = profiler.profile("gap").unwrap();
    assert_eq!(
        p.weekly_snapshots().len(),
        1,
        "Should have 1 finalized snapshot from week 0"
    );
    assert_eq!(p.weekly_snapshots()[0].total_messages, 10);
    assert!(
        p.rating > 50.0,
        "Normal conversations should keep rating above 50: {}",
        p.rating
    );
}

#[test]
fn skipped_weeks_gap_with_hostility_before_and_after() {
    let mut profiler = ContactProfiler::new();

    for w in 0..2 {
        for msg in 0..10 {
            profiler.record_event(&make_event(
                "gap_hostile",
                "conv_1",
                EventKind::Insult,
                w * WEEK_MS + msg * 1000,
            ));
        }
    }
    let rating_before_gap = profiler.profile("gap_hostile").unwrap().rating;

    for msg in 0..10 {
        profiler.record_event(&make_event(
            "gap_hostile",
            "conv_1",
            EventKind::Insult,
            6 * WEEK_MS + msg * 1000,
        ));
    }

    let p = profiler.profile("gap_hostile").unwrap();
    assert!(
        p.rating < rating_before_gap,
        "Rating should continue to decline after gap"
    );
    assert!(p.rating >= 0.0);
}

#[test]
fn skipped_weeks_long_absence_8_weeks() {
    let mut profiler = ContactProfiler::new();

    for msg in 0..10 {
        profiler.record_event(&make_event(
            "absent",
            "conv_1",
            EventKind::NormalConversation,
            msg * 1000,
        ));
    }
    let friendly_rating = profiler.profile("absent").unwrap().rating;

    for msg in 0..10 {
        profiler.record_event(&make_event(
            "absent",
            "conv_1",
            EventKind::PhysicalThreat,
            9 * WEEK_MS + msg * 1000,
        ));
    }

    let p = profiler.profile("absent").unwrap();
    assert!(
        p.rating < friendly_rating,
        "Rating should drop after hostile return"
    );
    assert!(!p.weekly_snapshots().is_empty());
}

#[test]
fn skipped_weeks_holiday_recovery_pattern() {
    let mut profiler = ContactProfiler::new();

    for w in 0..5 {
        for msg in 0..7 {
            profiler.record_event(&make_event(
                "school",
                "conv_1",
                EventKind::NormalConversation,
                w * WEEK_MS + msg * 1000,
            ));
        }
        for msg in 7..10 {
            profiler.record_event(&make_event(
                "school",
                "conv_1",
                EventKind::Insult,
                w * WEEK_MS + msg * 1000,
            ));
        }
    }
    let pre_holiday_rating = profiler.profile("school").unwrap().rating;

    for w in 5..13 {
        profiler.record_event(&make_event(
            "school",
            "conv_1",
            EventKind::NormalConversation,
            w * WEEK_MS + 1000,
        ));
    }
    let post_holiday_rating = profiler.profile("school").unwrap().rating;
    assert!(
        post_holiday_rating > pre_holiday_rating,
        "Rating should improve during holiday: pre={pre_holiday_rating} post={post_holiday_rating}"
    );

    for w in 13..17 {
        for msg in 0..5 {
            profiler.record_event(&make_event(
                "school",
                "conv_1",
                EventKind::NormalConversation,
                w * WEEK_MS + msg * 1000,
            ));
        }
        for msg in 5..10 {
            profiler.record_event(&make_event(
                "school",
                "conv_1",
                EventKind::Insult,
                w * WEEK_MS + msg * 1000,
            ));
        }
    }
    profiler.record_event(&make_event(
        "school",
        "conv_1",
        EventKind::Insult,
        17 * WEEK_MS + 1000,
    ));

    let final_rating = profiler.profile("school").unwrap().rating;
    assert!(
            final_rating < post_holiday_rating,
            "Rating should drop when hostility resumes: holiday={post_holiday_rating} final={final_rating}"
        );
}

#[test]
fn skipped_weeks_no_snapshots_during_gap() {
    let mut profiler = ContactProfiler::new();

    profiler.record_event(&make_event("g", "c", EventKind::NormalConversation, 0));
    profiler.record_event(&make_event(
        "g",
        "c",
        EventKind::NormalConversation,
        10 * WEEK_MS,
    ));

    let p = profiler.profile("g").unwrap();
    assert_eq!(
        p.weekly_snapshots().len(),
        1,
        "Gaps should not create empty snapshots, got {}",
        p.weekly_snapshots().len()
    );
}

#[test]
fn concurrent_interleaved_events_two_devices() {
    let mut profiler = ContactProfiler::new();

    for i in 0..20u64 {
        if i % 2 == 0 {
            profiler.record_event(&make_event(
                "friend",
                "conv_1",
                EventKind::NormalConversation,
                i * 500,
            ));
        } else {
            profiler.record_event(&make_event(
                "friend",
                "conv_2",
                EventKind::NormalConversation,
                i * 500,
            ));
        }
    }

    let profile = profiler.profile("friend").unwrap();
    assert_eq!(profile.total_messages, 20);
    assert_eq!(profile.conversation_count, 2);
    assert!((0.0..=100.0).contains(&profile.rating));
}

#[test]
fn concurrent_export_import_mid_conversation() {
    let mut profiler = ContactProfiler::new();

    for i in 0..5 {
        profiler.record_event(&make_event(
            "alice",
            "conv_1",
            EventKind::NormalConversation,
            i * 1000,
        ));
    }
    let mid_rating = profiler.profile("alice").unwrap().rating;

    let checkpoint = profiler.export();

    for i in 5..10 {
        profiler.record_event(&make_event("alice", "conv_1", EventKind::Insult, i * 1000));
    }
    let post_hostile_rating = profiler.profile("alice").unwrap().rating;
    assert!(post_hostile_rating < mid_rating);

    let mut device2 = ContactProfiler::new();
    device2.import(checkpoint);
    let device2_rating = device2.profile("alice").unwrap().rating;
    assert_eq!(
        device2_rating, mid_rating,
        "Device 2 should have checkpoint rating"
    );

    for i in 10..15 {
        device2.record_event(&make_event(
            "alice",
            "conv_1",
            EventKind::NormalConversation,
            i * 1000,
        ));
    }
    let device2_final = device2.profile("alice").unwrap().rating;
    assert!(
        device2_final > device2_rating,
        "Device 2 should improve with normal msgs"
    );
}

#[test]
fn concurrent_import_overwrites_stale_profile() {
    let mut device_a = ContactProfiler::new();
    device_a.record_event(&make_event(
        "bob",
        "conv_1",
        EventKind::NormalConversation,
        0,
    ));

    let mut server = ContactProfiler::new();
    for i in 0..20 {
        server.record_event(&make_event(
            "bob",
            "conv_1",
            EventKind::NormalConversation,
            i * 1000,
        ));
    }
    let server_state = server.export();

    device_a.import(server_state);
    let profile = device_a.profile("bob").unwrap();
    assert_eq!(
        profile.total_messages, 20,
        "Import should overwrite stale data"
    );
}

#[test]
fn concurrent_multiple_contacts_independent() {
    let mut profiler = ContactProfiler::new();

    for i in 0..10 {
        profiler.record_event(&make_event("alice", "conv_1", EventKind::Insult, i * 1000));
    }

    for i in 0..10 {
        profiler.record_event(&make_event(
            "bob",
            "conv_2",
            EventKind::DefenseOfVictim,
            i * 1000,
        ));
    }

    for i in 0..10 {
        profiler.record_event(&make_event(
            "charlie",
            "conv_3",
            EventKind::Flattery,
            i * 1000,
        ));
    }

    let alice = profiler.profile("alice").unwrap();
    let bob = profiler.profile("bob").unwrap();
    let charlie = profiler.profile("charlie").unwrap();

    assert!(
        alice.rating < 50.0,
        "Alice should have low rating: {}",
        alice.rating
    );
    assert!(
        bob.rating > 50.0,
        "Bob should have high rating: {}",
        bob.rating
    );
    assert!(
        charlie.rating < 50.0,
        "Charlie (grooming) should have slightly low rating: {}",
        charlie.rating
    );

    assert_eq!(alice.bullying_event_count, 10);
    assert_eq!(bob.bullying_event_count, 0);
    assert_eq!(charlie.grooming_event_count, 10);
}

#[test]
fn concurrent_export_import_preserves_all_contacts() {
    let mut profiler = ContactProfiler::new();

    for i in 0..50u64 {
        let sender = format!("user_{i}");
        for j in 0..5 {
            profiler.record_event(&make_event(
                &sender,
                "conv_1",
                EventKind::NormalConversation,
                j * 1000,
            ));
        }
    }

    let state = profiler.export();
    assert_eq!(state.profiles.len(), 50);

    let mut profiler2 = ContactProfiler::new();
    profiler2.import(state);

    for i in 0..50u64 {
        let sender = format!("user_{i}");
        let p = profiler2.profile(&sender);
        assert!(p.is_some(), "user_{i} should exist after import");
        assert_eq!(p.unwrap().total_messages, 5);
    }
}

#[test]
fn concurrent_cleanup_during_active_use() {
    let mut profiler = ContactProfiler::new();

    profiler.record_event(&make_event(
        "old_user",
        "conv_1",
        EventKind::NormalConversation,
        1000,
    ));

    let active_ts = 100 * DAY_MS;
    for i in 0..10 {
        profiler.record_event(&make_event(
            "active_user",
            "conv_1",
            EventKind::NormalConversation,
            active_ts + i * 1000,
        ));
    }

    profiler.cleanup(50 * DAY_MS);
    assert!(
        profiler.profile("old_user").is_none(),
        "Old user should be removed"
    );
    assert!(
        profiler.profile("active_user").is_some(),
        "Active user should survive"
    );

    profiler.record_event(&make_event(
        "active_user",
        "conv_1",
        EventKind::NormalConversation,
        active_ts + 20000,
    ));
    profiler.record_event(&make_event(
        "new_user",
        "conv_1",
        EventKind::Flattery,
        active_ts + 30000,
    ));

    assert_eq!(profiler.profile("active_user").unwrap().total_messages, 11);
    assert!(
        profiler.profile("new_user").is_some(),
        "New user after cleanup should work"
    );
}

#[test]
fn concurrent_import_then_mark_trusted() {
    let mut profiler1 = ContactProfiler::new();
    for i in 0..5 {
        profiler1.record_event(&make_event(
            "uncle",
            "conv_1",
            EventKind::NormalConversation,
            i * 1000,
        ));
    }
    let state = profiler1.export();

    let mut profiler2 = ContactProfiler::new();
    profiler2.import(state);
    profiler2.mark_trusted("uncle");

    let profile = profiler2.profile("uncle").unwrap();
    assert_eq!(profile.trust_level, 1.0);
    assert!(profile.is_trusted);

    for i in 0..5 {
        profiler2.record_event(&make_event(
            "uncle",
            "conv_1",
            EventKind::Insult,
            10000 + i * 1000,
        ));
    }
    let profile = profiler2.profile("uncle").unwrap();
    assert!(
        profile.trust_level < 1.0,
        "Trust should decay after import+mark+hostile"
    );
}

#[test]
fn concurrent_double_import_last_wins() {
    let mut profiler = ContactProfiler::new();

    let mut p1 = ContactProfiler::new();
    for i in 0..5 {
        p1.record_event(&make_event(
            "alice",
            "conv_1",
            EventKind::NormalConversation,
            i * 1000,
        ));
    }
    let state1 = p1.export();

    let mut p2 = ContactProfiler::new();
    for i in 0..5 {
        p2.record_event(&make_event("alice", "conv_1", EventKind::Insult, i * 1000));
    }
    let state2 = p2.export();

    let rating1 = p1.profile("alice").unwrap().rating;
    let rating2 = p2.profile("alice").unwrap().rating;
    assert!(
        rating1 > rating2,
        "State1 should have higher rating than state2"
    );

    profiler.import(state1);
    assert_eq!(profiler.profile("alice").unwrap().rating, rating1);
    profiler.import(state2);
    assert_eq!(
        profiler.profile("alice").unwrap().rating,
        rating2,
        "Second import should overwrite first"
    );
}

#[test]
fn concurrent_export_import_with_behavioral_snapshots() {
    let mut profiler = ContactProfiler::new();

    for w in 0..3 {
        for msg in 0..10 {
            profiler.record_event(&make_event(
                "contact",
                "conv_1",
                EventKind::NormalConversation,
                w * WEEK_MS + msg * 1000,
            ));
        }
    }
    for w in 3..6 {
        for msg in 0..6 {
            profiler.record_event(&make_event(
                "contact",
                "conv_1",
                EventKind::NormalConversation,
                w * WEEK_MS + msg * 1000,
            ));
        }
        for msg in 6..10 {
            profiler.record_event(&make_event(
                "contact",
                "conv_1",
                EventKind::Insult,
                w * WEEK_MS + msg * 1000,
            ));
        }
    }
    profiler.record_event(&make_event(
        "contact",
        "conv_1",
        EventKind::Insult,
        6 * WEEK_MS + 1000,
    ));

    let orig = profiler.profile("contact").unwrap();
    let orig_snapshots = orig.weekly_snapshots().len();
    let orig_trend = orig.trend;
    let orig_rating = orig.rating;

    let state = profiler.export();
    let mut profiler2 = ContactProfiler::new();
    profiler2.import(state);

    let imported = profiler2.profile("contact").unwrap();
    assert_eq!(imported.weekly_snapshots().len(), orig_snapshots);
    assert_eq!(imported.trend, orig_trend);
    assert_eq!(imported.rating, orig_rating);

    let signals = profiler2.check_behavioral_shift("contact");
    let orig_signals = profiler.check_behavioral_shift("contact");
    assert_eq!(
        signals.len(),
        orig_signals.len(),
        "Behavioral shift signals should match after import"
    );
}

#[test]
fn merge_import_preserves_local_profile() {
    let mut profiler_a = ContactProfiler::new();
    profiler_a.record_event(&make_event("alice", "conv_1", EventKind::Insult, 1000));
    profiler_a.record_event(&make_event("alice", "conv_1", EventKind::Insult, 2000));

    let mut profiler_b = ContactProfiler::new();
    profiler_b.record_event(&make_event(
        "alice",
        "conv_2",
        EventKind::NormalConversation,
        3000,
    ));

    let state_b = profiler_b.export();
    profiler_a.merge_import(state_b);

    let profile = profiler_a.profile("alice").unwrap();
    assert!(
        profile.bullying_event_count >= 2,
        "Should preserve higher bullying count from A"
    );
    assert!(
        profile.conversation_count >= 2,
        "Should have conversations from both A and B"
    );
}

#[test]
fn merge_import_takes_most_cautious_trust() {
    let mut profiler_a = ContactProfiler::new();
    profiler_a.record_event(&make_event(
        "alice",
        "conv_1",
        EventKind::NormalConversation,
        1000,
    ));
    profiler_a.mark_trusted("alice");

    let mut profiler_b = ContactProfiler::new();
    profiler_b.record_event(&make_event("alice", "conv_1", EventKind::Insult, 2000));
    let state_b = profiler_b.export();
    profiler_a.merge_import(state_b);

    let profile = profiler_a.profile("alice").unwrap();
    assert!(
        !profile.is_trusted,
        "Should take most cautious trust: false"
    );
}

#[test]
fn merge_import_inserts_new_profiles() {
    let mut profiler_a = ContactProfiler::new();
    profiler_a.record_event(&make_event(
        "alice",
        "conv_1",
        EventKind::NormalConversation,
        1000,
    ));

    let mut profiler_b = ContactProfiler::new();
    profiler_b.record_event(&make_event(
        "bob",
        "conv_2",
        EventKind::NormalConversation,
        2000,
    ));

    let state_b = profiler_b.export();
    profiler_a.merge_import(state_b);

    assert!(profiler_a.profile("alice").is_some());
    assert!(profiler_a.profile("bob").is_some());
}

#[test]
fn merge_import_takes_earliest_first_seen() {
    let mut profiler_a = ContactProfiler::new();
    profiler_a.record_event(&make_event(
        "alice",
        "conv_1",
        EventKind::NormalConversation,
        5000,
    ));

    let mut profiler_b = ContactProfiler::new();
    profiler_b.record_event(&make_event(
        "alice",
        "conv_1",
        EventKind::NormalConversation,
        1000,
    ));

    let state_b = profiler_b.export();
    profiler_a.merge_import(state_b);

    let profile = profiler_a.profile("alice").unwrap();
    assert_eq!(
        profile.first_seen_ms, 1000,
        "Should take earliest first_seen"
    );
}

#[test]
fn merge_import_preserves_fingerprint_frequency() {
    let mut profiler_a = ContactProfiler::new();
    let mut event_a = make_event("alice", "conv_1", EventKind::PropagandaNarrative, 1_000);
    event_a.subtype = Some("war_denial".to_string());
    event_a.content_hash = Some(777);
    profiler_a.record_event(&event_a);

    let mut profiler_b = ContactProfiler::new();
    for i in 0..5 {
        let mut event_b = make_event(
            "alice",
            "conv_1",
            EventKind::PropagandaNarrative,
            2_000 + i * 1_000,
        );
        event_b.subtype = Some("war_denial".to_string());
        event_b.content_hash = Some(777);
        profiler_b.record_event(&event_b);
    }

    profiler_a.merge_import(profiler_b.export());

    let profile = profiler_a.profile("alice").unwrap();
    let count = profile
        .message_fingerprints
        .iter()
        .filter(|&&fingerprint| fingerprint == 777)
        .count();
    assert!(count >= 5, "Expected repeated fingerprints to be preserved");
}

#[test]
fn merge_import_same_state_does_not_inflate_fingerprints() {
    let mut source = ContactProfiler::new();
    for i in 0..4 {
        let mut event = make_event(
            "alice",
            "conv_1",
            EventKind::PropagandaNarrative,
            1_000 + i * 1_000,
        );
        event.subtype = Some("war_denial".to_string());
        event.content_hash = Some(404);
        source.record_event(&event);
    }

    let state = source.export();
    let mut local = ContactProfiler::new();
    local.merge_import(state.clone());
    local.merge_import(state);

    let profile = local.profile("alice").unwrap();
    let count = profile
        .message_fingerprints
        .iter()
        .filter(|&&fingerprint| fingerprint == 404)
        .count();
    assert_eq!(
        count, 4,
        "Repeated merge of same state should not inflate counts"
    );
}

#[test]
fn merge_import_recomputes_narrative_diversity_from_union() {
    let mut profiler_a = ContactProfiler::new();
    let mut a = make_event("alice", "conv_1", EventKind::PropagandaNarrative, 1_000);
    a.subtype = Some("war_denial".to_string());
    profiler_a.record_event(&a);

    let mut profiler_b = ContactProfiler::new();
    let mut b = make_event("alice", "conv_1", EventKind::PropagandaNarrative, 2_000);
    b.subtype = Some("capitulation".to_string());
    profiler_b.record_event(&b);

    profiler_a.merge_import(profiler_b.export());

    let profile = profiler_a.profile("alice").unwrap();
    assert_eq!(
        profile.narrative_diversity, 2,
        "Narrative diversity should reflect merged unique narrative ids"
    );
}

#[test]
fn merge_import_same_state_does_not_inflate_weekly_counts() {
    let mut source = ContactProfiler::new();
    for i in 0..4 {
        let mut event = make_event(
            "alice",
            "conv_1",
            EventKind::PropagandaNarrative,
            1_000 + i * 1_000,
        );
        event.subtype = Some("war_denial".to_string());
        source.record_event(&event);
    }

    let state = source.export();
    let mut local = ContactProfiler::new();
    local.merge_import(state.clone());
    local.merge_import(state);

    let profile = local.profile("alice").unwrap();
    assert_eq!(profile.weekly_propaganda_counts.len(), 1);
    assert_eq!(
        profile.weekly_propaganda_counts[0].1, 4,
        "Repeated merge of same state should not inflate per-week counts"
    );
}

#[test]
fn merge_import_is_idempotent_for_same_state() {
    let mut source = ContactProfiler::new();
    for i in 0..6 {
        let mut event = make_event(
            "alice",
            "conv_1",
            EventKind::PropagandaNarrative,
            1_000 + i * 1_000,
        );
        event.subtype = Some("war_denial".to_string());
        event.content_hash = Some(901);
        source.record_event(&event);
    }
    for i in 0..3 {
        source.record_event(&make_event(
            "alice",
            "conv_1",
            EventKind::NormalConversation,
            20_000 + i * 1_000,
        ));
    }

    let state = source.export();
    let mut local = ContactProfiler::new();
    local.merge_import(state.clone());
    let before = local.profile("alice").unwrap().clone();
    local.merge_import(state);
    let after = local.profile("alice").unwrap().clone();

    assert_eq!(before.propaganda_event_count, after.propaganda_event_count);
    assert_eq!(
        before.propaganda_source_count,
        after.propaganda_source_count
    );
    assert_eq!(before.narrative_hits, after.narrative_hits);
    assert_eq!(before.narrative_diversity, after.narrative_diversity);
    assert_eq!(
        before.weekly_propaganda_counts,
        after.weekly_propaganda_counts
    );
    assert_eq!(before.message_fingerprints, after.message_fingerprints);
    assert!(
        (before.propaganda_score - after.propaganda_score).abs() < 1e-6,
        "Idempotent merge should keep propaganda_score stable"
    );
}

#[test]
fn merge_import_advances_behavioral_snapshot_to_incoming_superset() {
    let mut local = ContactProfiler::new();
    local.record_event(&make_event(
        "alice",
        "conv_1",
        EventKind::NormalConversation,
        1_000,
    ));

    let mut source = ContactProfiler::new();
    for timestamp_ms in [1_000, 2_000, 3_000] {
        source.record_event(&make_event(
            "alice",
            "conv_1",
            EventKind::NormalConversation,
            timestamp_ms,
        ));
    }

    local.merge_import(source.export());

    let profile = local.profile("alice").unwrap();
    let snapshot = profile.current_snapshot.as_ref().unwrap();
    assert_eq!(snapshot.total_messages, 3);
    assert_eq!(snapshot.neutral_count, 3);
    assert_eq!(profile.active_days.len(), 1);
}

#[test]
fn merge_import_preserves_most_cautious_average_severity() {
    let mut local = ContactProfiler::new();
    local.record_event(&make_event(
        "alice",
        "conv_1",
        EventKind::NormalConversation,
        1_000,
    ));
    {
        let profile = local.profiles.get_mut("alice").unwrap();
        profile.severity_sum = 2.0;
        profile.severity_count = 10;
    }

    let mut incoming = ContactProfiler::new();
    incoming.record_event(&make_event(
        "alice",
        "conv_2",
        EventKind::NormalConversation,
        2_000,
    ));
    {
        let profile = incoming.profiles.get_mut("alice").unwrap();
        profile.severity_sum = 8.0;
        profile.severity_count = 4;
    }

    local.merge_import(incoming.export());
    let profile = local.profile("alice").unwrap();
    assert_eq!(profile.severity_count, 10);
    assert!((profile.average_severity() - 2.0).abs() < 1e-6);
}

#[test]
fn wire_export_canonicalizes_equivalent_severity_accumulation() {
    let mut first = ContactProfiler::new();
    let mut second = ContactProfiler::new();
    let event = make_event("alice", "conv_1", EventKind::NormalConversation, 1_000);
    first.record_event(&event);
    second.record_event(&event);

    first.profiles.get_mut("alice").unwrap().severity_sum = 19.8;
    second.profiles.get_mut("alice").unwrap().severity_sum = 19.799_997;

    let first_wire = first.export_wire_state();
    let second_wire = second.export_wire_state();
    assert_eq!(
        first_wire.profiles[0].severity_sum.to_bits(),
        second_wire.profiles[0].severity_sum.to_bits()
    );
}

#[test]
fn merge_import_never_decreases_cautious_counters() {
    let mut local = ContactProfiler::new();
    let mut local_event = make_event("alice", "conv_1", EventKind::PropagandaNarrative, 1_000);
    local_event.subtype = Some("war_denial".to_string());
    local_event.content_hash = Some(777);
    local.record_event(&local_event);
    local.record_event(&make_event(
        "alice",
        "conv_1",
        EventKind::SuspiciousSource,
        2_000,
    ));

    let mut incoming_profiler = ContactProfiler::new();
    for i in 0..4 {
        let mut event = make_event(
            "alice",
            "conv_2",
            EventKind::PropagandaNarrative,
            3_000 + i * 1_000,
        );
        event.subtype = Some("capitulation".to_string());
        event.content_hash = Some(888);
        incoming_profiler.record_event(&event);
    }

    let before = local.profile("alice").unwrap().clone();
    local.merge_import(incoming_profiler.export());
    let after = local.profile("alice").unwrap().clone();

    assert!(after.propaganda_event_count >= before.propaganda_event_count);
    assert!(after.propaganda_source_count >= before.propaganda_source_count);
    assert!(after.narrative_diversity >= before.narrative_diversity);
    assert!(after.propaganda_conversations.len() >= before.propaganda_conversations.len());
    assert!(after.last_seen_ms >= before.last_seen_ms);
    assert!(after.first_seen_ms <= before.first_seen_ms);
}
