use std::collections::HashSet;
use std::sync::Arc;

use aura_domain::{
    DomainAction, DomainConfirmedOutput, DomainConversationType, DomainEventKind, DomainInput,
    DomainModuleId, DomainOutput, DomainRegistry, DomainRiskProfile, DomainSignal,
    DomainTemporalActorRole, DomainTemporalContext, DomainTemporalDirectionality,
    DomainTemporalEvent, DomainTemporalInput, DomainTemporalOutput, DomainTemporalSpeechAct,
    DomainTemporalStance, MlSafetyHint,
};
use aura_kids::KidsModule;
use aura_military::MilitaryModule;
use aura_patterns::{validate_ukraine_coordinates, BlockedUrlMatch};

use crate::action::{decide_action_v2, propaganda_action_for_subtype};
use crate::context::events::{EventDirectionality, EventKind, EventSpeechAct, EventStance};
use crate::context::observation::RawObservation;
use crate::context::propaganda::NarrativeId;
use crate::context::propaganda::PropagandaDetector;
use crate::context::tracker::ConversationTimeline;
use crate::types::{
    Action, ActionRecommendation, Confidence, ConversationType, DetectionSignal, ProtectionLevel,
    SignalFamily, ThreatType,
};
use crate::DomainMode;
use crate::{AuraConfig, AuraDomainModule, MessageInput};

pub struct AuraDomainRuntime {
    registry: DomainRegistry,
    kids_module: Arc<KidsModule>,
}

impl Default for AuraDomainRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl AuraDomainRuntime {
    pub fn new() -> Self {
        let mut registry = DomainRegistry::default();
        let kids_module = Arc::new(KidsModule::new());
        registry.register_arc(kids_module.clone());
        registry.register(MilitaryModule);
        Self {
            registry,
            kids_module,
        }
    }

    pub fn supports(&self, config: &AuraConfig) -> bool {
        self.supports_for_mode(config.effective_domain_mode())
    }

    pub fn supports_for_mode(&self, domain_mode: DomainMode) -> bool {
        let Some(module_id) = domain_module_id_for_mode(domain_mode) else {
            return true;
        };
        self.registry.contains(module_id)
    }

    pub fn analyze(&self, config: &AuraConfig, input: &MessageInput) -> Option<DomainOutput> {
        self.analyze_for_mode_with_protection(
            config.effective_domain_mode(),
            config.effective_protection_level(),
            input,
        )
    }

    pub fn export_kids_memory(&self) -> aura_kids::pipeline::ExportedKidsMemoryState {
        self.kids_module.export_memory()
    }

    pub fn import_kids_memory(&self, state: &aura_kids::pipeline::ExportedKidsMemoryState) -> bool {
        self.kids_module.import_memory(state)
    }

    pub fn clear_kids_memory(&self) {
        self.kids_module.clear_memory();
    }

    pub fn kids_conversation_risk_score(&self, conversation_id: &str) -> f32 {
        self.kids_module.conversation_risk_score(conversation_id)
    }

    pub fn kids_conversation_escalation_message_count(&self, conversation_id: &str) -> u32 {
        self.kids_module
            .conversation_escalation_message_count(conversation_id)
    }

    pub fn kids_sender_cross_risk_score(&self, sender_id: &str) -> f32 {
        self.kids_module.sender_cross_risk_score(sender_id)
    }

    pub fn apply_kids_guardian_feedback(
        &self,
        sender_id: &str,
        conversation_id: &str,
        verdict: aura_kids::pipeline::GuardianVerdict,
    ) {
        self.kids_module
            .apply_guardian_feedback(sender_id, conversation_id, verdict);
    }

    pub fn analyze_for_mode(
        &self,
        domain_mode: DomainMode,
        input: &MessageInput,
    ) -> Option<DomainOutput> {
        self.analyze_for_mode_with_protection(domain_mode, ProtectionLevel::Medium, input)
    }

    pub fn analyze_for_mode_with_protection(
        &self,
        domain_mode: DomainMode,
        protection_level: ProtectionLevel,
        input: &MessageInput,
    ) -> Option<DomainOutput> {
        self.analyze_for_mode_with_hints(domain_mode, protection_level, input, None)
    }

    pub fn analyze_for_mode_with_hints(
        &self,
        domain_mode: DomainMode,
        protection_level: ProtectionLevel,
        input: &MessageInput,
        ml_safety_hint: Option<MlSafetyHint>,
    ) -> Option<DomainOutput> {
        let module_id = domain_module_id_for_mode(domain_mode)?;
        let domain_input = build_domain_input(domain_mode, protection_level, input, ml_safety_hint);
        self.registry.run(module_id, &domain_input)
    }

    /// Detects domain candidates without updating domain-owned memory.
    pub fn detect_for_mode_with_hints(
        &self,
        domain_mode: DomainMode,
        protection_level: ProtectionLevel,
        input: &MessageInput,
        ml_safety_hint: Option<MlSafetyHint>,
    ) -> Option<DomainOutput> {
        let module_id = domain_module_id_for_mode(domain_mode)?;
        let domain_input = build_domain_input(domain_mode, protection_level, input, ml_safety_hint);
        self.registry.run_detection(module_id, &domain_input)
    }

    /// Commits only candidates and ML hints that survived core interpretation.
    pub fn commit_confirmed_for_mode_with_hints(
        &self,
        domain_mode: DomainMode,
        protection_level: ProtectionLevel,
        input: &MessageInput,
        confirmed_ml_safety_hint: Option<MlSafetyHint>,
        confirmed_signals: &[DomainSignal],
    ) -> Option<DomainConfirmedOutput> {
        let module_id = domain_module_id_for_mode(domain_mode)?;
        let domain_input = build_domain_input(
            domain_mode,
            protection_level,
            input,
            confirmed_ml_safety_hint,
        );
        self.registry
            .commit_confirmed(module_id, &domain_input, confirmed_signals)
    }

    pub fn analyze_temporal_for_mode(
        &self,
        domain_mode: DomainMode,
        input: &MessageInput,
        timestamp_ms: u64,
        content_hash: Option<u64>,
        timeline: Option<&ConversationTimeline>,
        protected_account_id: Option<&str>,
    ) -> Option<DomainTemporalOutput> {
        let module_id = domain_module_id_for_mode(domain_mode)?;
        if !self.registry.temporal_enabled(module_id) {
            return None;
        }
        let temporal_input = build_domain_temporal_input(
            input,
            timestamp_ms,
            content_hash,
            timeline?,
            protected_account_id,
        )?;
        self.registry.run_temporal(module_id, &temporal_input)
    }
}

fn build_domain_input(
    domain_mode: DomainMode,
    protection_level: ProtectionLevel,
    input: &MessageInput,
    ml_safety_hint: Option<MlSafetyHint>,
) -> DomainInput {
    DomainInput {
        text: input.text.clone(),
        language: input.language.clone(),
        sender_id: Some(input.sender_id.0.clone()),
        conversation_id: Some(input.conversation_id.0.clone()),
        risk_profile: domain_risk_profile_for_mode(domain_mode, protection_level),
        conversation_type: domain_conversation_type(input.conversation_type),
        ml_safety_hint,
    }
}

fn build_domain_temporal_input(
    input: &MessageInput,
    timestamp_ms: u64,
    content_hash: Option<u64>,
    timeline: &ConversationTimeline,
    protected_account_id: Option<&str>,
) -> Option<DomainTemporalInput> {
    let mut actors: Vec<&str> = timeline
        .all_events()
        .iter()
        .filter(|event| event.timestamp_ms <= timestamp_ms)
        .map(|event| event.sender_id.0.as_str())
        .collect();
    actors.push(input.sender_id.0.as_str());
    actors.sort_unstable();
    actors.dedup();

    let current_actor_id = actor_id(&actors, &input.sender_id.0)?;
    let events = timeline
        .all_events()
        .iter()
        .filter(|event| event.timestamp_ms <= timestamp_ms)
        .filter_map(|event| {
            let kind = temporal_event_kind(&event.kind)?;
            Some(DomainTemporalEvent {
                event_id: event.event_id,
                timestamp_ms: event.timestamp_ms,
                actor_id: actor_id(&actors, &event.sender_id.0)?,
                actor_role: temporal_actor_role(&event.sender_id.0, protected_account_id),
                kind,
                confidence: event.confidence,
                content_hash: event.content_hash,
                context: DomainTemporalContext {
                    speech_act: temporal_speech_act(event.context.speech_act),
                    stance: temporal_stance(event.context.stance),
                    directionality: temporal_directionality(event.context.directionality),
                    trusted_contact: event.context.trusted_contact,
                    confidence: event.context.confidence,
                },
            })
        })
        .collect();

    Some(DomainTemporalInput {
        as_of_ms: timestamp_ms,
        current_actor_id,
        current_content_hash: content_hash,
        conversation_type: domain_conversation_type(input.conversation_type),
        events,
    })
}

fn actor_id(actors: &[&str], sender_id: &str) -> Option<u32> {
    let index = actors.binary_search(&sender_id).ok()?;
    u32::try_from(index).ok()
}

fn temporal_actor_role(
    sender_id: &str,
    protected_account_id: Option<&str>,
) -> DomainTemporalActorRole {
    if protected_account_id.is_some_and(|protected| protected == sender_id) {
        DomainTemporalActorRole::ProtectedAccount
    } else {
        DomainTemporalActorRole::External
    }
}

fn temporal_event_kind(kind: &EventKind) -> Option<DomainEventKind> {
    match kind {
        EventKind::PropagandaNarrative => Some(DomainEventKind::PropagandaNarrative),
        EventKind::SuspiciousSource => Some(DomainEventKind::SuspiciousSource),
        EventKind::PositionLeak => Some(DomainEventKind::PositionLeak),
        EventKind::UnitInfoLeak => Some(DomainEventKind::UnitInfoLeak),
        EventKind::EquipmentLeak => Some(DomainEventKind::EquipmentLeak),
        EventKind::CoordinateMention => Some(DomainEventKind::CoordinateMention),
        EventKind::PsyopsPattern => Some(DomainEventKind::PsyopsPattern),
        EventKind::IntelGathering => Some(DomainEventKind::IntelGathering),
        EventKind::MilitaryPhishing => Some(DomainEventKind::MilitaryPhishing),
        EventKind::MilitaryDisinfo => Some(DomainEventKind::MilitaryDisinfo),
        _ => None,
    }
}

fn temporal_speech_act(speech_act: EventSpeechAct) -> DomainTemporalSpeechAct {
    match speech_act {
        EventSpeechAct::Unknown => DomainTemporalSpeechAct::Unknown,
        EventSpeechAct::Assert => DomainTemporalSpeechAct::Assert,
        EventSpeechAct::Ask => DomainTemporalSpeechAct::Ask,
        EventSpeechAct::Quote => DomainTemporalSpeechAct::Quote,
        EventSpeechAct::Report => DomainTemporalSpeechAct::Report,
        EventSpeechAct::Counter => DomainTemporalSpeechAct::Counter,
        EventSpeechAct::Support => DomainTemporalSpeechAct::Support,
        EventSpeechAct::Solicit => DomainTemporalSpeechAct::Solicit,
    }
}

fn temporal_stance(stance: EventStance) -> DomainTemporalStance {
    match stance {
        EventStance::Unknown => DomainTemporalStance::Unknown,
        EventStance::Endorse => DomainTemporalStance::Endorse,
        EventStance::Oppose => DomainTemporalStance::Oppose,
        EventStance::Neutral => DomainTemporalStance::Neutral,
        EventStance::Ambiguous => DomainTemporalStance::Ambiguous,
    }
}

fn temporal_directionality(directionality: EventDirectionality) -> DomainTemporalDirectionality {
    match directionality {
        EventDirectionality::Unknown => DomainTemporalDirectionality::Unknown,
        EventDirectionality::DirectedAtUser => DomainTemporalDirectionality::DirectedAtUser,
        EventDirectionality::SelfReferential => DomainTemporalDirectionality::SelfReferential,
        EventDirectionality::ThirdParty => DomainTemporalDirectionality::ThirdParty,
        EventDirectionality::Broadcast => DomainTemporalDirectionality::Broadcast,
    }
}

fn domain_module_id_for_mode(domain_mode: DomainMode) -> Option<DomainModuleId> {
    match domain_mode.domain_module() {
        Some(AuraDomainModule::Kids) => Some(DomainModuleId::Kids),
        Some(AuraDomainModule::Military) => Some(DomainModuleId::Military),
        None => None,
    }
}

fn domain_risk_profile_for_mode(
    domain_mode: DomainMode,
    protection_level: ProtectionLevel,
) -> DomainRiskProfile {
    let is_kids = match domain_mode.domain_module() {
        Some(AuraDomainModule::Kids) => true,
        Some(AuraDomainModule::Military) => false,
        None => false,
    };
    if !is_kids {
        return DomainRiskProfile::Normal;
    }
    match protection_level {
        ProtectionLevel::High => DomainRiskProfile::Strict,
        ProtectionLevel::Off | ProtectionLevel::Low | ProtectionLevel::Medium => {
            DomainRiskProfile::Normal
        }
    }
}

fn domain_conversation_type(conversation_type: ConversationType) -> DomainConversationType {
    match conversation_type {
        ConversationType::Direct => DomainConversationType::Direct,
        ConversationType::Group => DomainConversationType::Group,
    }
}

pub fn map_pattern_rule_to_event_kind(rule_id: &str) -> Option<EventKind> {
    aura_patterns::event_kind_for_rule(rule_id).map(event_kind_from_pattern)
}

fn event_kind_from_pattern(kind: aura_patterns::PatternEventKind) -> EventKind {
    match kind {
        aura_patterns::PatternEventKind::HarmEncouragement => EventKind::HarmEncouragement,
        aura_patterns::PatternEventKind::Denigration => EventKind::Denigration,
        aura_patterns::PatternEventKind::Exclusion => EventKind::Exclusion,
        aura_patterns::PatternEventKind::Mockery => EventKind::Mockery,
        aura_patterns::PatternEventKind::Insult => EventKind::Insult,
        aura_patterns::PatternEventKind::SecrecyRequest => EventKind::SecrecyRequest,
        aura_patterns::PatternEventKind::GiftOffer => EventKind::GiftOffer,
        aura_patterns::PatternEventKind::MeetingRequest => EventKind::MeetingRequest,
        aura_patterns::PatternEventKind::PersonalInfoRequest => EventKind::PersonalInfoRequest,
        aura_patterns::PatternEventKind::Flattery => EventKind::Flattery,
        aura_patterns::PatternEventKind::PhotoRequest => EventKind::PhotoRequest,
        aura_patterns::PatternEventKind::PlatformSwitch => EventKind::PlatformSwitch,
        aura_patterns::PatternEventKind::SexualContent => EventKind::SexualContent,
        aura_patterns::PatternEventKind::EmotionalBlackmail => EventKind::EmotionalBlackmail,
        aura_patterns::PatternEventKind::VideoCallRequest => EventKind::VideoCallRequest,
        aura_patterns::PatternEventKind::LocationRequest => EventKind::LocationRequest,
        aura_patterns::PatternEventKind::MoneyOffer => EventKind::MoneyOffer,
        aura_patterns::PatternEventKind::SuicidalIdeation => EventKind::SuicidalIdeation,
        aura_patterns::PatternEventKind::Hopelessness => EventKind::Hopelessness,
        aura_patterns::PatternEventKind::Devaluation => EventKind::Devaluation,
        aura_patterns::PatternEventKind::Gaslighting => EventKind::Gaslighting,
        aura_patterns::PatternEventKind::GuiltTripping => EventKind::GuiltTripping,
        aura_patterns::PatternEventKind::PeerPressure => EventKind::PeerPressure,
        aura_patterns::PatternEventKind::Darvo => EventKind::Darvo,
        aura_patterns::PatternEventKind::SuicideCoercion => EventKind::SuicideCoercion,
        aura_patterns::PatternEventKind::FalseConsensus => EventKind::FalseConsensus,
        aura_patterns::PatternEventKind::DebtCreation => EventKind::DebtCreation,
        aura_patterns::PatternEventKind::ReputationThreat => EventKind::ReputationThreat,
        aura_patterns::PatternEventKind::IdentityErosion => EventKind::IdentityErosion,
        aura_patterns::PatternEventKind::NetworkPoisoning => EventKind::NetworkPoisoning,
        aura_patterns::PatternEventKind::FakeVulnerability => EventKind::FakeVulnerability,
        aura_patterns::PatternEventKind::DoxxingAttempt => EventKind::DoxxingAttempt,
        aura_patterns::PatternEventKind::ScreenshotThreat => EventKind::ScreenshotThreat,
        aura_patterns::PatternEventKind::HateSpeech => EventKind::HateSpeech,
        aura_patterns::PatternEventKind::PiiSelfDisclosure => EventKind::PiiSelfDisclosure,
        aura_patterns::PatternEventKind::CasualMeetingRequest => EventKind::CasualMeetingRequest,
        aura_patterns::PatternEventKind::DareChallenge => EventKind::DareChallenge,
        aura_patterns::PatternEventKind::SuspiciousSource => EventKind::SuspiciousSource,
        aura_patterns::PatternEventKind::CoordinateMention => EventKind::CoordinateMention,
        aura_patterns::PatternEventKind::PositionLeak => EventKind::PositionLeak,
        aura_patterns::PatternEventKind::UnitInfoLeak => EventKind::UnitInfoLeak,
        aura_patterns::PatternEventKind::EquipmentLeak => EventKind::EquipmentLeak,
        aura_patterns::PatternEventKind::MilitaryPhishing => EventKind::MilitaryPhishing,
        aura_patterns::PatternEventKind::IntelGathering => EventKind::IntelGathering,
        aura_patterns::PatternEventKind::MilitaryDisinfo => EventKind::MilitaryDisinfo,
    }
}

pub fn event_kind_from_domain(kind: DomainEventKind) -> EventKind {
    match kind {
        DomainEventKind::Flattery => EventKind::Flattery,
        DomainEventKind::GiftOffer => EventKind::GiftOffer,
        DomainEventKind::SecrecyRequest => EventKind::SecrecyRequest,
        DomainEventKind::PlatformSwitch => EventKind::PlatformSwitch,
        DomainEventKind::PersonalInfoRequest => EventKind::PersonalInfoRequest,
        DomainEventKind::PhotoRequest => EventKind::PhotoRequest,
        DomainEventKind::VideoCallRequest => EventKind::VideoCallRequest,
        DomainEventKind::FinancialGrooming => EventKind::FinancialGrooming,
        DomainEventKind::MeetingRequest => EventKind::MeetingRequest,
        DomainEventKind::SexualContent => EventKind::SexualContent,
        DomainEventKind::AgeInappropriate => EventKind::AgeInappropriate,
        DomainEventKind::Insult => EventKind::Insult,
        DomainEventKind::Denigration => EventKind::Denigration,
        DomainEventKind::HarmEncouragement => EventKind::HarmEncouragement,
        DomainEventKind::PhysicalThreat => EventKind::PhysicalThreat,
        DomainEventKind::RumorSpreading => EventKind::RumorSpreading,
        DomainEventKind::Exclusion => EventKind::Exclusion,
        DomainEventKind::Mockery => EventKind::Mockery,
        DomainEventKind::GuiltTripping => EventKind::GuiltTripping,
        DomainEventKind::Gaslighting => EventKind::Gaslighting,
        DomainEventKind::EmotionalBlackmail => EventKind::EmotionalBlackmail,
        DomainEventKind::PeerPressure => EventKind::PeerPressure,
        DomainEventKind::LoveBombing => EventKind::LoveBombing,
        DomainEventKind::Darvo => EventKind::Darvo,
        DomainEventKind::Devaluation => EventKind::Devaluation,
        DomainEventKind::SuicidalIdeation => EventKind::SuicidalIdeation,
        DomainEventKind::Hopelessness => EventKind::Hopelessness,
        DomainEventKind::FarewellMessage => EventKind::FarewellMessage,
        DomainEventKind::DoxxingAttempt => EventKind::DoxxingAttempt,
        DomainEventKind::ScreenshotThreat => EventKind::ScreenshotThreat,
        DomainEventKind::HateSpeech => EventKind::HateSpeech,
        DomainEventKind::LocationRequest => EventKind::LocationRequest,
        DomainEventKind::MoneyOffer => EventKind::MoneyOffer,
        DomainEventKind::PiiSelfDisclosure => EventKind::PiiSelfDisclosure,
        DomainEventKind::CasualMeetingRequest => EventKind::CasualMeetingRequest,
        DomainEventKind::DareChallenge => EventKind::DareChallenge,
        DomainEventKind::SuicideCoercion => EventKind::SuicideCoercion,
        DomainEventKind::FalseConsensus => EventKind::FalseConsensus,
        DomainEventKind::DebtCreation => EventKind::DebtCreation,
        DomainEventKind::ReputationThreat => EventKind::ReputationThreat,
        DomainEventKind::IdentityErosion => EventKind::IdentityErosion,
        DomainEventKind::NetworkPoisoning => EventKind::NetworkPoisoning,
        DomainEventKind::FakeVulnerability => EventKind::FakeVulnerability,
        DomainEventKind::PropagandaNarrative => EventKind::PropagandaNarrative,
        DomainEventKind::SuspiciousSource => EventKind::SuspiciousSource,
        DomainEventKind::PositionLeak => EventKind::PositionLeak,
        DomainEventKind::UnitInfoLeak => EventKind::UnitInfoLeak,
        DomainEventKind::EquipmentLeak => EventKind::EquipmentLeak,
        DomainEventKind::CoordinateMention => EventKind::CoordinateMention,
        DomainEventKind::PsyopsPattern => EventKind::PsyopsPattern,
        DomainEventKind::IntelGathering => EventKind::IntelGathering,
        DomainEventKind::MilitaryPhishing => EventKind::MilitaryPhishing,
        DomainEventKind::MilitaryDisinfo => EventKind::MilitaryDisinfo,
    }
}

pub fn map_domain_threat_to_event_kind(threat_type: ThreatType) -> Option<EventKind> {
    match threat_type {
        ThreatType::OpsecViolation => Some(EventKind::PositionLeak),
        ThreatType::Psyops => Some(EventKind::PsyopsPattern),
        ThreatType::MilitarySocialEng => Some(EventKind::IntelGathering),
        ThreatType::CoordinateLeak => Some(EventKind::CoordinateMention),
        ThreatType::None
        | ThreatType::Bullying
        | ThreatType::Grooming
        | ThreatType::Explicit
        | ThreatType::Threat
        | ThreatType::SelfHarm
        | ThreatType::Spam
        | ThreatType::Scam
        | ThreatType::Phishing
        | ThreatType::Manipulation
        | ThreatType::Nsfw
        | ThreatType::HateSpeech
        | ThreatType::Doxxing
        | ThreatType::PiiLeakage
        | ThreatType::Propaganda => None,
    }
}

pub fn map_threat_to_event_kind(threat_type: ThreatType) -> Option<EventKind> {
    match threat_type {
        ThreatType::Grooming => Some(EventKind::SecrecyRequest),
        ThreatType::Bullying => Some(EventKind::Insult),
        ThreatType::Threat => Some(EventKind::PhysicalThreat),
        ThreatType::SelfHarm => Some(EventKind::SuicidalIdeation),
        ThreatType::Manipulation => Some(EventKind::GuiltTripping),
        ThreatType::Doxxing => Some(EventKind::DoxxingAttempt),
        ThreatType::HateSpeech => Some(EventKind::HateSpeech),
        ThreatType::PiiLeakage => Some(EventKind::PiiSelfDisclosure),
        ThreatType::Propaganda => Some(EventKind::PropagandaNarrative),
        ThreatType::None
        | ThreatType::Explicit
        | ThreatType::Spam
        | ThreatType::Scam
        | ThreatType::Phishing
        | ThreatType::Nsfw => None,
        ThreatType::OpsecViolation
        | ThreatType::Psyops
        | ThreatType::MilitarySocialEng
        | ThreatType::CoordinateLeak => map_domain_threat_to_event_kind(threat_type),
    }
}

pub fn map_rule_or_threat_to_event_kind(
    rule_id: &str,
    threat_type: ThreatType,
) -> Option<EventKind> {
    if let Some(kind) = map_pattern_rule_to_event_kind(rule_id) {
        return Some(kind);
    }
    map_threat_to_event_kind(threat_type)
}

pub fn map_ml_signal_to_event_kind(threat_type: ThreatType) -> Option<EventKind> {
    match threat_type {
        ThreatType::Bullying => Some(EventKind::Insult),
        ThreatType::Threat => Some(EventKind::PhysicalThreat),
        ThreatType::Explicit => Some(EventKind::SexualContent),
        ThreatType::None
        | ThreatType::Grooming
        | ThreatType::SelfHarm
        | ThreatType::Spam
        | ThreatType::Scam
        | ThreatType::Phishing
        | ThreatType::Manipulation
        | ThreatType::Nsfw
        | ThreatType::HateSpeech
        | ThreatType::Doxxing
        | ThreatType::PiiLeakage
        | ThreatType::Propaganda
        | ThreatType::OpsecViolation
        | ThreatType::Psyops
        | ThreatType::MilitarySocialEng
        | ThreatType::CoordinateLeak => None,
    }
}

pub fn domain_detection_enabled(config: &AuraConfig, threat_type: ThreatType) -> Option<bool> {
    match threat_type {
        ThreatType::Propaganda => Some(config.propaganda_detection_enabled()),
        ThreatType::OpsecViolation | ThreatType::CoordinateLeak => {
            Some(config.opsec_detection_enabled())
        }
        ThreatType::Psyops | ThreatType::MilitarySocialEng => {
            Some(config.psyops_detection_enabled())
        }
        ThreatType::None
        | ThreatType::Bullying
        | ThreatType::Grooming
        | ThreatType::Explicit
        | ThreatType::Threat
        | ThreatType::SelfHarm
        | ThreatType::Spam
        | ThreatType::Scam
        | ThreatType::Phishing
        | ThreatType::Manipulation
        | ThreatType::Nsfw
        | ThreatType::HateSpeech
        | ThreatType::Doxxing
        | ThreatType::PiiLeakage => None,
    }
}

pub fn detection_enabled_for_threat(config: &AuraConfig, threat_type: ThreatType) -> bool {
    let Some(enabled) = domain_detection_enabled(config, threat_type) else {
        return match threat_type {
            ThreatType::Grooming => config.grooming_detection_enabled(),
            ThreatType::SelfHarm => config.self_harm_detection_enabled(),
            ThreatType::Bullying => config.bullying_detection_enabled(),
            ThreatType::Threat
            | ThreatType::Phishing
            | ThreatType::Explicit
            | ThreatType::Spam
            | ThreatType::Nsfw
            | ThreatType::Scam
            | ThreatType::Manipulation
            | ThreatType::HateSpeech
            | ThreatType::Doxxing
            | ThreatType::PiiLeakage => config.protection_enabled(),
            ThreatType::None => false,
            ThreatType::Propaganda
            | ThreatType::OpsecViolation
            | ThreatType::Psyops
            | ThreatType::MilitarySocialEng
            | ThreatType::CoordinateLeak => false,
        };
    };
    enabled
}

pub fn is_propaganda_threat(threat_type: ThreatType) -> bool {
    match threat_type {
        ThreatType::Propaganda => true,
        ThreatType::None
        | ThreatType::Bullying
        | ThreatType::Grooming
        | ThreatType::Explicit
        | ThreatType::Threat
        | ThreatType::SelfHarm
        | ThreatType::Spam
        | ThreatType::Scam
        | ThreatType::Phishing
        | ThreatType::Manipulation
        | ThreatType::Nsfw
        | ThreatType::HateSpeech
        | ThreatType::Doxxing
        | ThreatType::PiiLeakage
        | ThreatType::OpsecViolation
        | ThreatType::Psyops
        | ThreatType::MilitarySocialEng
        | ThreatType::CoordinateLeak => false,
    }
}

pub fn is_link_family_threat(threat_type: ThreatType) -> bool {
    match threat_type {
        ThreatType::Phishing | ThreatType::MilitarySocialEng | ThreatType::Propaganda => true,
        ThreatType::None
        | ThreatType::Bullying
        | ThreatType::Grooming
        | ThreatType::Explicit
        | ThreatType::Threat
        | ThreatType::SelfHarm
        | ThreatType::Spam
        | ThreatType::Scam
        | ThreatType::Manipulation
        | ThreatType::Nsfw
        | ThreatType::HateSpeech
        | ThreatType::Doxxing
        | ThreatType::PiiLeakage
        | ThreatType::OpsecViolation
        | ThreatType::Psyops
        | ThreatType::CoordinateLeak => false,
    }
}

pub fn parse_domain_threat_type(s: &str) -> Option<ThreatType> {
    match s {
        "propaganda" => Some(ThreatType::Propaganda),
        "opsec_violation" => Some(ThreatType::OpsecViolation),
        "psyops" => Some(ThreatType::Psyops),
        "military_social_eng" => Some(ThreatType::MilitarySocialEng),
        "coordinate_leak" => Some(ThreatType::CoordinateLeak),
        _ => None,
    }
}

pub fn domain_threat_priority(threat_type: ThreatType) -> Option<u8> {
    match threat_type {
        ThreatType::OpsecViolation | ThreatType::CoordinateLeak => Some(2),
        ThreatType::Psyops => Some(5),
        ThreatType::MilitarySocialEng => Some(6),
        ThreatType::Propaganda => Some(7),
        ThreatType::None
        | ThreatType::Bullying
        | ThreatType::Grooming
        | ThreatType::Explicit
        | ThreatType::Threat
        | ThreatType::SelfHarm
        | ThreatType::Spam
        | ThreatType::Scam
        | ThreatType::Phishing
        | ThreatType::Manipulation
        | ThreatType::Nsfw
        | ThreatType::HateSpeech
        | ThreatType::Doxxing
        | ThreatType::PiiLeakage => None,
    }
}

pub fn threat_priority_for_sort(threat_type: ThreatType) -> u8 {
    if let Some(priority) = domain_threat_priority(threat_type) {
        return priority;
    }
    match threat_type {
        ThreatType::SelfHarm => 0,
        ThreatType::Grooming => 1,
        ThreatType::Explicit => 2,
        ThreatType::Threat => 3,
        ThreatType::Doxxing => 4,
        ThreatType::PiiLeakage => 5,
        ThreatType::Manipulation => 6,
        ThreatType::HateSpeech => 7,
        ThreatType::Bullying => 8,
        ThreatType::Nsfw => 9,
        ThreatType::Phishing => 10,
        ThreatType::Scam => 11,
        ThreatType::Spam => 12,
        ThreatType::None => 13,
        ThreatType::Propaganda
        | ThreatType::OpsecViolation
        | ThreatType::Psyops
        | ThreatType::MilitarySocialEng
        | ThreatType::CoordinateLeak => 13,
    }
}

pub fn is_domain_threat(threat_type: ThreatType) -> bool {
    match threat_type {
        ThreatType::Propaganda
        | ThreatType::OpsecViolation
        | ThreatType::Psyops
        | ThreatType::MilitarySocialEng
        | ThreatType::CoordinateLeak => true,
        ThreatType::None
        | ThreatType::Bullying
        | ThreatType::Grooming
        | ThreatType::Explicit
        | ThreatType::Threat
        | ThreatType::SelfHarm
        | ThreatType::Spam
        | ThreatType::Scam
        | ThreatType::Phishing
        | ThreatType::Manipulation
        | ThreatType::Nsfw
        | ThreatType::HateSpeech
        | ThreatType::Doxxing
        | ThreatType::PiiLeakage => false,
    }
}

pub fn parse_threat_type_label(s: &str) -> ThreatType {
    match s {
        "bullying" => ThreatType::Bullying,
        "grooming" => ThreatType::Grooming,
        "explicit" => ThreatType::Explicit,
        "threat" => ThreatType::Threat,
        "self_harm" => ThreatType::SelfHarm,
        "spam" => ThreatType::Spam,
        "scam" => ThreatType::Scam,
        "phishing" => ThreatType::Phishing,
        "manipulation" => ThreatType::Manipulation,
        "nsfw" => ThreatType::Nsfw,
        "hate_speech" => ThreatType::HateSpeech,
        "doxxing" => ThreatType::Doxxing,
        "pii_leakage" => ThreatType::PiiLeakage,
        other => parse_domain_threat_type(other).unwrap_or(ThreatType::None),
    }
}

pub fn domain_signal_threat_type(threat_type_hint: Option<&str>) -> ThreatType {
    let Some(threat_type_hint) = threat_type_hint else {
        return ThreatType::None;
    };
    let parsed = parse_threat_type_label(threat_type_hint);
    if parsed == ThreatType::None {
        ThreatType::None
    } else {
        parsed
    }
}

pub fn domain_signal_confidence(severity: Option<&str>, score: f32) -> Confidence {
    match severity {
        Some("critical") | Some("high") => Confidence::High,
        Some("medium") => Confidence::Medium,
        Some("low") => Confidence::Low,
        Some(_) | None => confidence_from_score(score),
    }
}

pub fn core_action_from_domain_action(action: DomainAction) -> Action {
    match action {
        DomainAction::Allow => Action::Allow,
        DomainAction::Mark => Action::Mark,
        DomainAction::Warn => Action::Warn,
        DomainAction::Block => Action::Block,
    }
}

pub fn domain_action_reason_marker(action: DomainAction) -> &'static str {
    match action {
        DomainAction::Allow => "domain.action.allow",
        DomainAction::Mark => "domain.action.mark",
        DomainAction::Warn => "domain.action.warn",
        DomainAction::Block => "domain.action.block",
    }
}

fn domain_signal_reason_code(signal: &aura_domain::DomainSignal) -> String {
    if signal.reason_code.is_empty() {
        format!("domain.{}", signal.threat_key)
    } else {
        format!("domain.{}", signal.reason_code)
    }
}

/// Projects domain candidates through the final core signal set.
///
/// Candidates absent from `active_signals` were rejected by contextual
/// interpretation. When context lowered a candidate's score, domain-owned
/// action, priority, and severity overrides are removed so they cannot undo
/// that decision during the post-confirmation policy pass.
pub(crate) fn context_confirmed_domain_signals(
    domain_output: Option<&DomainOutput>,
    active_signals: &[DetectionSignal],
) -> Vec<DomainSignal> {
    let Some(domain_output) = domain_output else {
        return Vec::new();
    };

    domain_output
        .signals
        .iter()
        .filter_map(|candidate| {
            let reason_code = domain_signal_reason_code(candidate);
            let active = active_signals.iter().find(|active| {
                active.reason_code == reason_code
                    && (active.threat_subtype.is_empty()
                        || active.threat_subtype == candidate.threat_key)
            })?;
            let mut confirmed = candidate.clone();
            let adjusted_score = if active.score.is_finite() {
                active.score.clamp(0.0, 1.0)
            } else {
                0.0
            };
            if adjusted_score + f32::EPSILON < confirmed.score {
                confirmed.action = None;
                confirmed.priority = None;
                confirmed.severity = None;
            }
            confirmed.score = adjusted_score;
            Some(confirmed)
        })
        .collect()
}

pub fn push_domain_reason_codes(reason_codes: &mut Vec<String>, domain_output: &DomainOutput) {
    for signal in &domain_output.signals {
        let reason_code = &signal.reason_code;
        if !reason_code.is_empty() {
            let reason_code = format!("domain.{reason_code}");
            if !reason_codes.contains(&reason_code) {
                reason_codes.push(reason_code);
            }
        }
        let threat_key = &signal.threat_key;
        if !threat_key.is_empty() {
            let marker = format!("domain.threat.{threat_key}");
            if !reason_codes.contains(&marker) {
                reason_codes.push(marker);
            }
        }
    }
}

fn push_active_domain_signal_reason_codes(
    reason_codes: &mut Vec<String>,
    domain_signals: &[aura_domain::DomainSignal],
    active_signals: &[DetectionSignal],
) -> bool {
    let mut found_active_signal = false;
    for signal in domain_signals {
        let active_reason = domain_signal_reason_code(signal);
        if !active_signals
            .iter()
            .any(|active| active.reason_code == active_reason)
        {
            continue;
        }
        found_active_signal = true;
        let reason_code = &signal.reason_code;
        if !reason_code.is_empty() {
            let reason_code = format!("domain.{reason_code}");
            if !reason_codes.contains(&reason_code) {
                reason_codes.push(reason_code);
            }
        }
        let threat_key = &signal.threat_key;
        if !threat_key.is_empty() {
            let marker = format!("domain.threat.{threat_key}");
            if !reason_codes.contains(&marker) {
                reason_codes.push(marker);
            }
        }
    }
    found_active_signal
}

pub fn merge_domain_output_effects(
    reason_codes: &mut Vec<String>,
    current_action: Action,
    domain_output: Option<&DomainOutput>,
) -> Action {
    let Some(domain_output) = domain_output else {
        return current_action;
    };

    push_domain_reason_codes(reason_codes, domain_output);
    merge_domain_action(reason_codes, current_action, domain_output)
}

pub(crate) fn merge_active_confirmed_domain_output_effects(
    reason_codes: &mut Vec<String>,
    current_action: Action,
    domain_output: Option<&DomainConfirmedOutput>,
    active_signals: &[DetectionSignal],
) -> Action {
    let Some(domain_output) = domain_output else {
        return current_action;
    };

    let confirmed_active = push_active_domain_signal_reason_codes(
        reason_codes,
        &domain_output.confirmed_signals,
        active_signals,
    );
    let derived_active = push_active_domain_signal_reason_codes(
        reason_codes,
        &domain_output.derived_signals,
        active_signals,
    );
    if !confirmed_active && !derived_active {
        return current_action;
    }

    merge_domain_action_value(reason_codes, current_action, domain_output.action)
}

pub(crate) fn merge_active_domain_temporal_output_effects(
    reason_codes: &mut Vec<String>,
    current_action: Action,
    domain_output: Option<&DomainTemporalOutput>,
    active_signals: &[DetectionSignal],
) -> Action {
    let Some(domain_output) = domain_output else {
        return current_action;
    };

    if !push_active_domain_signal_reason_codes(reason_codes, &domain_output.signals, active_signals)
    {
        return current_action;
    }

    merge_domain_action_value(reason_codes, current_action, domain_output.action)
}

fn merge_domain_action(
    reason_codes: &mut Vec<String>,
    current_action: Action,
    domain_output: &DomainOutput,
) -> Action {
    merge_domain_action_value(reason_codes, current_action, domain_output.action)
}

fn merge_domain_action_value(
    reason_codes: &mut Vec<String>,
    current_action: Action,
    action: Option<DomainAction>,
) -> Action {
    let Some(action) = action else {
        return current_action;
    };
    let action_marker = domain_action_reason_marker(action);
    if !reason_codes.iter().any(|code| code == action_marker) {
        reason_codes.push(action_marker.to_string());
    }

    let domain_action = core_action_from_domain_action(action);
    if domain_action > current_action {
        domain_action
    } else {
        current_action
    }
}

pub fn build_domain_observations(
    domain_output: Option<&DomainOutput>,
    content_hash: Option<u64>,
) -> Vec<RawObservation> {
    let Some(domain_output) = domain_output else {
        return Vec::new();
    };

    let mut observations = Vec::with_capacity(domain_output.signals.len());
    for (signal_index, domain_signal) in domain_output.signals.iter().enumerate() {
        let threat_type = domain_signal_threat_type(domain_signal.threat_type.as_deref());
        if threat_type == ThreatType::None {
            continue;
        }

        let reason = domain_signal_reason_code(domain_signal);
        let confidence =
            domain_signal_confidence(domain_signal.severity.as_deref(), domain_signal.score);
        let signal = DetectionSignal::context(
            threat_type,
            domain_signal.score,
            confidence,
            SignalFamily::Content,
            reason,
            "Domain module signal",
        )
        .with_threat_subtype(domain_signal.threat_key.clone());
        let subtype = (!signal.threat_subtype.is_empty()).then(|| signal.threat_subtype.clone());

        let observation = match domain_output.event_kind_for_signal(signal_index) {
            Some(kind) => RawObservation::signal_with_event(
                signal,
                event_kind_from_domain(kind),
                domain_signal.score,
                subtype,
                content_hash,
            ),
            None => RawObservation::signal(signal),
        };
        observations.push(observation);
    }
    observations
}

pub fn build_domain_temporal_signals(
    domain_output: Option<&DomainTemporalOutput>,
) -> Vec<DetectionSignal> {
    let Some(domain_output) = domain_output else {
        return Vec::new();
    };

    domain_output
        .signals
        .iter()
        .filter_map(|domain_signal| {
            let threat_type = domain_signal_threat_type(domain_signal.threat_type.as_deref());
            (threat_type != ThreatType::None).then(|| {
                DetectionSignal::context(
                    threat_type,
                    domain_signal.score,
                    domain_signal_confidence(
                        domain_signal.severity.as_deref(),
                        domain_signal.score,
                    ),
                    SignalFamily::Conversation,
                    domain_signal_reason_code(domain_signal),
                    "Domain temporal fusion signal",
                )
                .with_threat_subtype(domain_signal.threat_key.clone())
            })
        })
        .collect()
}

pub(crate) fn build_domain_memory_signals(
    domain_output: Option<&DomainConfirmedOutput>,
) -> Vec<DetectionSignal> {
    let Some(domain_output) = domain_output else {
        return Vec::new();
    };

    domain_output
        .derived_signals
        .iter()
        .filter_map(|domain_signal| {
            let threat_type = domain_signal_threat_type(domain_signal.threat_type.as_deref());
            (threat_type != ThreatType::None).then(|| {
                DetectionSignal::context(
                    threat_type,
                    domain_signal.score,
                    domain_signal_confidence(
                        domain_signal.severity.as_deref(),
                        domain_signal.score,
                    ),
                    SignalFamily::Conversation,
                    domain_signal_reason_code(domain_signal),
                    "Domain memory signal after contextual confirmation",
                )
                .with_threat_subtype(domain_signal.threat_key.clone())
            })
        })
        .collect()
}

pub fn build_blocked_url_signal(blocked: &BlockedUrlMatch) -> DetectionSignal {
    let threat_type = parse_threat_type_label(&blocked.threat_type);
    let reason_code = blocked_url_reason_code(threat_type, &blocked.rule_id);
    let explanation = format!("{}: {}", blocked.explanation, blocked.url);
    let threat_subtype =
        map_pattern_threat_subtype(&blocked.rule_id, threat_type, Some(&blocked.url));

    let mut signal = DetectionSignal::pattern(
        threat_type,
        blocked.score,
        confidence_from_score(blocked.score),
        reason_code,
        explanation,
    );
    if is_link_family_threat(threat_type) {
        signal.family = SignalFamily::Link;
    }
    if let Some(threat_subtype) = threat_subtype {
        signal = signal.with_threat_subtype(threat_subtype);
    }
    signal
}

pub fn decide_action_with_domain_overrides(
    threat_type: ThreatType,
    score: f32,
    protection_level: ProtectionLevel,
    reason_code: &str,
) -> (Action, ActionRecommendation) {
    if is_propaganda_threat(threat_type) {
        propaganda_action_for_subtype(score, protection_level, reason_code)
    } else {
        decide_action_v2(threat_type, score, protection_level)
    }
}

fn blocked_url_reason_code(threat_type: ThreatType, rule_id: &str) -> String {
    if threat_type == ThreatType::Phishing {
        "link.blocked_domain".to_string()
    } else {
        format!("pattern.{rule_id}")
    }
}

pub fn confidence_from_score(score: f32) -> Confidence {
    if score >= 0.8 {
        Confidence::High
    } else if score >= 0.5 {
        Confidence::Medium
    } else {
        Confidence::Low
    }
}

pub fn should_skip_pattern_rule_override(
    rule_id: &str,
    matched_rule_ids: &HashSet<String>,
) -> bool {
    aura_patterns::is_shadowed_generic_coordinate_rule(rule_id, matched_rule_ids)
}

pub fn should_skip_pattern_match(
    text: &str,
    threat_type: ThreatType,
    rule_id: &str,
    matched_text: Option<&str>,
) -> bool {
    if threat_type == ThreatType::Propaganda {
        let Some(matched_text) = matched_text else {
            return false;
        };
        let text_lower = text.to_lowercase();
        let matched_text = matched_text.to_lowercase();
        let Some(pos) = text_lower.find(&matched_text) else {
            return false;
        };
        if PropagandaDetector::check_false_positive_context(&text_lower, pos) {
            return true;
        }
    }

    if aura_patterns::requires_ukraine_coordinate_validation(rule_id) {
        let Some(matched_text) = matched_text else {
            return false;
        };
        if validate_ukraine_coordinates(matched_text).is_empty() {
            return true;
        }
    }
    false
}

pub fn map_pattern_threat_subtype(
    rule_id: &str,
    threat_type: ThreatType,
    matched_text: Option<&str>,
) -> Option<String> {
    let subtype = match threat_type {
        ThreatType::Propaganda => NarrativeId::from_rule_id(rule_id)
            .map(|narrative| narrative.tag())
            .or_else(|| propaganda_source_subtype(rule_id)),
        ThreatType::Psyops => aura_patterns::military_threat_subtype(
            rule_id,
            aura_patterns::MilitaryPatternFamily::Psyops,
            matched_text,
        ),
        ThreatType::MilitarySocialEng => aura_patterns::military_threat_subtype(
            rule_id,
            aura_patterns::MilitaryPatternFamily::SocialEngineering,
            matched_text,
        ),
        ThreatType::CoordinateLeak => aura_patterns::military_threat_subtype(
            rule_id,
            aura_patterns::MilitaryPatternFamily::CoordinateLeak,
            matched_text,
        ),
        ThreatType::OpsecViolation => aura_patterns::military_threat_subtype(
            rule_id,
            aura_patterns::MilitaryPatternFamily::Opsec,
            matched_text,
        ),
        ThreatType::None
        | ThreatType::Bullying
        | ThreatType::Grooming
        | ThreatType::Explicit
        | ThreatType::Threat
        | ThreatType::SelfHarm
        | ThreatType::Spam
        | ThreatType::Scam
        | ThreatType::Phishing
        | ThreatType::Manipulation
        | ThreatType::Nsfw
        | ThreatType::HateSpeech
        | ThreatType::Doxxing
        | ThreatType::PiiLeakage => None,
    };
    subtype.map(ToString::to_string)
}

fn propaganda_source_subtype(rule_id: &str) -> Option<&'static str> {
    if rule_id.starts_with("propaganda_domain_state_") {
        Some("state_media")
    } else if rule_id.starts_with("propaganda_domain_aligned_") {
        Some("aligned_media")
    } else if rule_id.starts_with("propaganda_domain_occupation_") {
        Some("occupation_media")
    } else if rule_id.starts_with("propaganda_domain_disinfo_") {
        Some("disinfo_infra")
    } else if rule_id.starts_with("propaganda_telegram_channel_") {
        Some("telegram_channel")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_blocked_url_signal, build_domain_observations, build_domain_temporal_input,
        build_domain_temporal_signals, context_confirmed_domain_signals,
        core_action_from_domain_action, decide_action_with_domain_overrides,
        detection_enabled_for_threat, domain_action_reason_marker, domain_conversation_type,
        domain_risk_profile_for_mode, domain_signal_confidence, domain_signal_threat_type,
        domain_threat_priority, event_kind_from_domain, is_domain_threat, is_link_family_threat,
        is_propaganda_threat, map_domain_threat_to_event_kind, map_ml_signal_to_event_kind,
        map_pattern_threat_subtype, map_rule_or_threat_to_event_kind, map_threat_to_event_kind,
        merge_active_domain_temporal_output_effects, merge_domain_output_effects,
        parse_domain_threat_type, parse_threat_type_label, should_skip_pattern_match,
        should_skip_pattern_rule_override, threat_priority_for_sort,
    };

    use crate::context::events::{
        ContextEvent, EventContextFrame, EventDirectionality, EventKind, EventSpeechAct,
        EventStance,
    };
    use crate::context::tracker::{ConversationTracker, TrackerConfig};
    use crate::ids::{ConversationId, SenderId};
    use crate::types::{
        Action, Confidence, ContentType, ConversationType, DetectionSignal, ProtectionLevel,
        SignalFamily, ThreatType,
    };
    use crate::{AuraConfig, AuraDomainRuntime, DomainMode, MessageInput};
    use aura_domain::{
        DomainAction, DomainEventKind, DomainOutput, DomainSignal, DomainTemporalOutput,
    };
    use aura_patterns::BlockedUrlMatch;
    use std::collections::HashSet;

    fn temporal_message(sender_id: &str) -> MessageInput {
        MessageInput {
            content_type: ContentType::Text,
            text: Some("content is intentionally not projected".to_string()),
            image_data: None,
            sender_id: SenderId::from(sender_id),
            conversation_id: ConversationId::from("temporal-conversation"),
            language: Some("uk".to_string()),
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        }
    }

    fn temporal_event(
        sender_id: &str,
        kind: EventKind,
        timestamp_ms: u64,
        content_hash: u64,
    ) -> ContextEvent {
        let mut event =
            ContextEvent::new(timestamp_ms, sender_id, "temporal-conversation", kind, 0.9)
                .with_context(EventContextFrame {
                    speech_act: EventSpeechAct::Assert,
                    stance: EventStance::Endorse,
                    directionality: EventDirectionality::DirectedAtUser,
                    confidence: 0.9,
                    ..EventContextFrame::default()
                });
        event.content_hash = Some(content_hash);
        event
    }

    #[test]
    fn temporal_projection_is_exact_after_tracker_restart() {
        let mut tracker = ConversationTracker::new(TrackerConfig::default());
        tracker.record_event(temporal_event(
            "external",
            EventKind::PropagandaNarrative,
            1_000,
            11,
        ));
        tracker.record_event(temporal_event(
            "external",
            EventKind::PsyopsPattern,
            2_000,
            22,
        ));
        let input = temporal_message("external");
        let before = build_domain_temporal_input(
            &input,
            2_000,
            Some(22),
            tracker
                .timeline("temporal-conversation")
                .expect("source timeline"),
            Some("protected"),
        )
        .expect("source projection");

        let state = tracker.export_wire_state();
        let mut restored = ConversationTracker::new(TrackerConfig::default());
        restored.import_wire_state(state).expect("state import");
        let after = build_domain_temporal_input(
            &input,
            2_000,
            Some(22),
            restored
                .timeline("temporal-conversation")
                .expect("restored timeline"),
            Some("protected"),
        )
        .expect("restored projection");

        assert_eq!(before, after);
    }

    #[test]
    fn temporal_projection_excludes_future_events_from_backfill() {
        let mut tracker = ConversationTracker::new(TrackerConfig::default());
        tracker.record_event(temporal_event(
            "external",
            EventKind::PropagandaNarrative,
            1_000,
            11,
        ));
        tracker.record_event(temporal_event(
            "external",
            EventKind::PsyopsPattern,
            3_000,
            33,
        ));
        let input = temporal_message("external");

        let projection = build_domain_temporal_input(
            &input,
            1_000,
            Some(11),
            tracker.timeline("temporal-conversation").expect("timeline"),
            Some("protected"),
        )
        .expect("projection");

        assert_eq!(projection.events.len(), 1);
    }

    #[test]
    fn temporal_action_requires_its_derived_signal_to_be_active() {
        let output = DomainTemporalOutput {
            signals: vec![DomainSignal {
                threat_key: "military_temporal_collection".to_string(),
                reason_code: "military.temporal.collection".to_string(),
                score: 0.9,
                threat_type: Some("military_social_eng".to_string()),
                severity: Some("high".to_string()),
                priority: Some(90),
                action: Some(DomainAction::Warn),
            }],
            action: Some(DomainAction::Warn),
        };
        let active_signals = build_domain_temporal_signals(Some(&output));
        let mut active_reason_codes = Vec::new();
        let active_action = merge_active_domain_temporal_output_effects(
            &mut active_reason_codes,
            Action::Allow,
            Some(&output),
            &active_signals,
        );

        assert_eq!(active_action, Action::Warn);
        assert!(active_reason_codes
            .iter()
            .any(|code| code == "domain.action.warn"));

        let mut inactive_reason_codes = Vec::new();
        let inactive_action = merge_active_domain_temporal_output_effects(
            &mut inactive_reason_codes,
            Action::Allow,
            Some(&output),
            &[],
        );
        assert_eq!(inactive_action, Action::Allow);
        assert!(inactive_reason_codes.is_empty());
    }

    #[test]
    fn invalid_disabled_minor_config_remains_fail_closed() {
        let config = AuraConfig {
            account_type: crate::types::AccountType::Child,
            enabled: false,
            ..AuraConfig::default()
        };

        for threat_type in [
            ThreatType::Threat,
            ThreatType::Phishing,
            ThreatType::Explicit,
            ThreatType::Spam,
            ThreatType::Nsfw,
            ThreatType::Scam,
            ThreatType::Manipulation,
            ThreatType::HateSpeech,
            ThreatType::Doxxing,
            ThreatType::PiiLeakage,
        ] {
            assert!(
                detection_enabled_for_threat(&config, threat_type),
                "{threat_type:?} must remain active for an invalid disabled minor config"
            );
        }
    }

    #[test]
    fn typed_domain_event_bridge_is_name_agnostic() {
        assert_eq!(
            event_kind_from_domain(DomainEventKind::MilitaryPhishing),
            EventKind::MilitaryPhishing
        );
        assert_eq!(
            event_kind_from_domain(DomainEventKind::CoordinateMention),
            EventKind::CoordinateMention
        );
        assert_eq!(
            event_kind_from_domain(DomainEventKind::SecrecyRequest),
            EventKind::SecrecyRequest
        );
        assert_eq!(
            event_kind_from_domain(DomainEventKind::ScreenshotThreat),
            EventKind::ScreenshotThreat
        );
    }

    #[test]
    fn unrouted_domain_signal_does_not_gain_an_event_from_text_fields() {
        let output = DomainOutput {
            signals: vec![DomainSignal {
                threat_key: "opaque_signal".to_string(),
                reason_code: "opaque.reason".to_string(),
                score: 0.9,
                threat_type: Some("grooming".to_string()),
                ..DomainSignal::default()
            }],
            action: None,
            routes: Vec::new(),
        };

        let observations = build_domain_observations(Some(&output), None);

        assert_eq!(observations.len(), 1);
        assert!(observations[0].signal.is_some());
        assert!(observations[0].event_hint.is_none());
    }

    #[test]
    fn military_threat_mapping_works() {
        assert_eq!(
            map_domain_threat_to_event_kind(ThreatType::MilitarySocialEng),
            Some(EventKind::IntelGathering)
        );
        assert_eq!(
            map_domain_threat_to_event_kind(ThreatType::CoordinateLeak),
            Some(EventKind::CoordinateMention)
        );
        assert_eq!(
            map_threat_to_event_kind(ThreatType::Grooming),
            Some(EventKind::SecrecyRequest)
        );
        assert_eq!(
            map_rule_or_threat_to_event_kind("grooming_secrecy_001", ThreatType::None),
            Some(EventKind::SecrecyRequest)
        );
        assert_eq!(
            map_ml_signal_to_event_kind(ThreatType::Explicit),
            Some(EventKind::SexualContent)
        );
        assert_eq!(map_ml_signal_to_event_kind(ThreatType::Psyops), None);
        assert!(is_propaganda_threat(ThreatType::Propaganda));
        assert!(!is_propaganda_threat(ThreatType::Threat));
        assert!(is_link_family_threat(ThreatType::MilitarySocialEng));
        assert_eq!(
            parse_domain_threat_type("opsec_violation"),
            Some(ThreatType::OpsecViolation)
        );
        assert_eq!(parse_domain_threat_type("self_harm"), None);
        assert_eq!(domain_threat_priority(ThreatType::Psyops), Some(5));
        assert_eq!(domain_threat_priority(ThreatType::Threat), None);
        assert!(is_domain_threat(ThreatType::CoordinateLeak));
        assert!(!is_domain_threat(ThreatType::SelfHarm));
        assert_eq!(
            parse_threat_type_label("propaganda"),
            ThreatType::Propaganda
        );
        assert_eq!(threat_priority_for_sort(ThreatType::Threat), 3);
        let config = AuraConfig {
            enabled: false,
            ..AuraConfig::default()
        };
        assert!(!detection_enabled_for_threat(&config, ThreatType::Threat));
        assert_eq!(
            domain_signal_threat_type(Some("military_social_eng")),
            ThreatType::MilitarySocialEng
        );
        assert_eq!(
            domain_signal_confidence(Some("critical"), 0.2),
            crate::types::Confidence::High
        );
        assert_eq!(
            core_action_from_domain_action(DomainAction::Warn),
            Action::Warn
        );
        assert_eq!(
            domain_action_reason_marker(DomainAction::Block),
            "domain.action.block"
        );

        let domain_output = DomainOutput::routed(
            vec![DomainSignal {
                threat_key: "grooming.secrecy".to_string(),
                reason_code: "kids.grooming.secrecy".to_string(),
                score: 0.91,
                severity: Some("high".to_string()),
                priority: Some(95),
                action: None,
                threat_type: Some("grooming".to_string()),
            }],
            None,
            |_| Some(DomainEventKind::SecrecyRequest),
        );
        let observations = build_domain_observations(Some(&domain_output), Some(42));
        assert_eq!(observations.len(), 1);
        assert_eq!(
            observations[0]
                .signal
                .as_ref()
                .map(|signal| signal.threat_type),
            Some(ThreatType::Grooming)
        );
        assert_eq!(
            observations[0]
                .event_hint
                .as_ref()
                .map(|hint| hint.kind.clone()),
            Some(EventKind::SecrecyRequest)
        );
        let blocked_signal = build_blocked_url_signal(&BlockedUrlMatch {
            url: "http://bad.tld".to_string(),
            domain: "bad.tld".to_string(),
            matched_domain: "bad.tld".to_string(),
            rule_id: "url_block".to_string(),
            threat_type: "phishing".to_string(),
            score: 0.99,
            explanation: "Blocked URL".to_string(),
        });
        assert_eq!(blocked_signal.reason_code, "link.blocked_domain");
        assert_eq!(blocked_signal.threat_type, ThreatType::Phishing);

        let mut reason_codes = Vec::new();
        let action =
            merge_domain_output_effects(&mut reason_codes, Action::Allow, Some(&domain_output));
        assert_eq!(action, Action::Allow);
        assert!(reason_codes
            .iter()
            .any(|code| code == "domain.kids.grooming.secrecy"));
        let (action, _) = decide_action_with_domain_overrides(
            ThreatType::Propaganda,
            0.8,
            ProtectionLevel::Medium,
            "domain.propaganda.dehumanization",
        );
        assert_eq!(action, Action::Warn);
    }

    #[test]
    fn contextual_confirmation_rejects_absent_candidates_and_neutralizes_softened_overrides() {
        let candidate = DomainSignal {
            threat_key: "kids_selfharm_crisis".to_string(),
            reason_code: "kids.selfharm.crisis".to_string(),
            score: 0.98,
            severity: Some("critical".to_string()),
            priority: Some(100),
            action: Some(DomainAction::Warn),
            threat_type: Some("self_harm".to_string()),
        };
        let output = DomainOutput::routed(vec![candidate], Some(DomainAction::Warn), |_| {
            Some(DomainEventKind::SuicidalIdeation)
        });

        assert!(context_confirmed_domain_signals(Some(&output), &[]).is_empty());

        let active = DetectionSignal::context(
            ThreatType::SelfHarm,
            0.42,
            Confidence::Low,
            SignalFamily::Content,
            "domain.kids.selfharm.crisis",
            "softened by interpreted context",
        )
        .with_threat_subtype("kids_selfharm_crisis");
        let confirmed = context_confirmed_domain_signals(Some(&output), &[active]);

        assert_eq!(confirmed.len(), 1);
        assert!((confirmed[0].score - 0.42).abs() < f32::EPSILON);
        assert_eq!(confirmed[0].action, None);
        assert_eq!(confirmed[0].priority, None);
        assert_eq!(confirmed[0].severity, None);
    }

    #[test]
    fn military_subtype_mapping_works() {
        assert_eq!(
            map_pattern_threat_subtype(
                "military_phishing_diia_001",
                ThreatType::MilitarySocialEng,
                None,
            ),
            Some("phishing_diia".to_string())
        );
        assert_eq!(
            map_pattern_threat_subtype(
                "opsec_coordinates_ukraine_dd_001",
                ThreatType::CoordinateLeak,
                None,
            ),
            Some("ukraine_dd".to_string())
        );
        assert_eq!(
            map_pattern_threat_subtype(
                "psyops_surrender_001",
                ThreatType::Psyops,
                Some("Скажи Волга"),
            ),
            Some("surrender_volga".to_string())
        );
        assert_eq!(
            map_pattern_threat_subtype("propaganda_domain_state_001", ThreatType::Propaganda, None),
            Some("state_media".to_string())
        );
    }

    #[test]
    fn skips_generic_coordinate_rule_outside_ukraine() {
        assert!(should_skip_pattern_match(
            "55.7558, 37.6173",
            ThreatType::CoordinateLeak,
            "opsec_coordinates_001",
            Some("55.7558, 37.6173"),
        ));
        assert!(!should_skip_pattern_match(
            "48.8566, 30.3522",
            ThreatType::CoordinateLeak,
            "opsec_coordinates_001",
            Some("48.8566, 30.3522"),
        ));
    }

    #[test]
    fn suppresses_generic_coordinate_when_domain_specific_rule_present() {
        let mut matched_rule_ids = HashSet::new();
        matched_rule_ids.insert("opsec_coordinates_ukraine_dd_001".to_string());
        assert!(should_skip_pattern_rule_override(
            "opsec_coordinates_001",
            &matched_rule_ids
        ));
    }

    #[test]
    fn none_domain_mode_disables_domain_runtime_output() {
        let runtime = AuraDomainRuntime::new();
        let input = MessageInput {
            content_type: ContentType::Text,
            text: Some("don't tell your parents, this is our little secret".to_string()),
            image_data: None,
            sender_id: SenderId::from("sender"),
            conversation_id: ConversationId::from("conv"),
            language: Some("en".to_string()),
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        };
        let output = runtime.analyze_for_mode(DomainMode::None, &input);
        assert!(output.is_none());
    }

    #[test]
    fn selected_domain_mode_runs_matching_domain_module() {
        let runtime = AuraDomainRuntime::new();
        let input = MessageInput {
            content_type: ContentType::Text,
            text: Some("Please complete this diia security update now.".to_string()),
            image_data: None,
            sender_id: SenderId::from("sender"),
            conversation_id: ConversationId::from("conv"),
            language: Some("en".to_string()),
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        };
        let output = runtime
            .analyze_for_mode(DomainMode::Military, &input)
            .expect("military mode should run");
        assert!(
            output
                .signals
                .iter()
                .any(|signal| signal.reason_code.contains("military")),
            "Expected military domain signal, got {:?}",
            output.signals
        );
    }

    #[test]
    fn kids_domain_uses_strict_profile_on_high_protection() {
        assert_eq!(
            domain_risk_profile_for_mode(DomainMode::Kids, ProtectionLevel::High),
            aura_domain::DomainRiskProfile::Strict
        );
        assert_eq!(
            domain_risk_profile_for_mode(DomainMode::Kids, ProtectionLevel::Medium),
            aura_domain::DomainRiskProfile::Normal
        );
        assert_eq!(
            domain_risk_profile_for_mode(DomainMode::Military, ProtectionLevel::High),
            aura_domain::DomainRiskProfile::Normal
        );
        assert_eq!(
            domain_conversation_type(ConversationType::Direct),
            aura_domain::DomainConversationType::Direct
        );
        assert_eq!(
            domain_conversation_type(ConversationType::Group),
            aura_domain::DomainConversationType::Group
        );
    }
}
