use std::collections::HashSet;
use std::sync::Arc;

use aura_domain::{
    DomainAction, DomainConversationType, DomainInput, DomainModuleId, DomainOutput,
    DomainRegistry, DomainRiskProfile, MlSafetyHint,
};
use aura_kids::KidsModule;
use aura_military::MilitaryModule;
use aura_patterns::{validate_ukraine_coordinates, BlockedUrlMatch};

use crate::action::{decide_action_v2, propaganda_action_for_subtype};
use crate::context::events::EventKind;
use crate::context::observation::RawObservation;
use crate::context::propaganda::NarrativeId;
use crate::context::propaganda::PropagandaDetector;
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

    pub fn import_kids_memory(&self, state: &aura_kids::pipeline::ExportedKidsMemoryState) {
        self.kids_module.import_memory(state);
    }

    pub fn clear_kids_memory(&self) {
        self.kids_module.clear_memory();
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
        self.analyze_for_mode_with_hints(domain_mode, protection_level, input, None, None)
    }

    pub fn analyze_for_mode_with_hints(
        &self,
        domain_mode: DomainMode,
        protection_level: ProtectionLevel,
        input: &MessageInput,
        ml_safety_hint: Option<MlSafetyHint>,
        server_sender_risk_hint: Option<f32>,
    ) -> Option<DomainOutput> {
        let module_id = domain_module_id_for_mode(domain_mode)?;
        let risk_profile = domain_risk_profile_for_mode(domain_mode, protection_level);
        let conversation_type = domain_conversation_type(input.conversation_type);
        let domain_input = DomainInput {
            text: input.text.clone(),
            language: input.language.clone(),
            sender_id: Some(input.sender_id.0.clone()),
            conversation_id: Some(input.conversation_id.0.clone()),
            risk_profile,
            conversation_type,
            ml_safety_hint,
            server_sender_risk_hint,
        };
        self.registry.run(module_id, &domain_input)
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

pub fn map_domain_rule_to_event_kind(rule_id: &str) -> Option<EventKind> {
    if rule_id.contains("kids.grooming.secrecy") || rule_id.contains("kids.grooming.offplatform") {
        return Some(EventKind::SecrecyRequest);
    }
    if rule_id.contains("kids.grooming.trust_isolation")
        || rule_id.contains("kids.grooming.controlled_secrecy_compound")
    {
        return Some(EventKind::Exclusion);
    }
    if rule_id.contains("kids.bullying.group_pile_on")
        || rule_id.contains("kids.bullying.harassment")
    {
        return Some(EventKind::Insult);
    }
    if rule_id.contains("kids.bullying.public_humiliation") {
        return Some(EventKind::ReputationThreat);
    }
    if rule_id.contains("kids.selfharm.acute")
        || rule_id.contains("kids.selfharm.ideation")
        || rule_id.contains("kids.selfharm.planning_window")
    {
        return Some(EventKind::SuicidalIdeation);
    }
    if rule_id.contains("kids.manipulation.blackmail") {
        return Some(EventKind::EmotionalBlackmail);
    }
    if rule_id.contains("kids.manipulation.image_sextortion")
        || rule_id.contains("kids.memory.sustained_sextortion")
    {
        return Some(EventKind::ScreenshotThreat);
    }
    if rule_id.contains("kids.manipulation.gaslight") {
        return Some(EventKind::Gaslighting);
    }
    if rule_id.contains("kids.manipulation.suicide_coercion") {
        return Some(EventKind::SuicideCoercion);
    }
    if rule_id.contains("kids.manipulation.deadline_compliance") {
        return Some(EventKind::PeerPressure);
    }
    if rule_id.contains("kids.bullying.selfharm_compound") {
        return Some(EventKind::SuicidalIdeation);
    }
    if rule_id.contains("kids.selfharm.coercion_compound") {
        return Some(EventKind::SuicideCoercion);
    }
    if rule_id.contains("kids.memory.grooming_progression") {
        return Some(EventKind::SecrecyRequest);
    }
    if rule_id.contains("kids.memory.sender_risk_accumulation") {
        return Some(EventKind::EmotionalBlackmail);
    }
    if rule_id.contains("kids.memory.new_sender_fast_escalation") {
        return Some(EventKind::EmotionalBlackmail);
    }
    if rule_id.contains("kids.memory.cross_conversation_repeat_offender") {
        return Some(EventKind::EmotionalBlackmail);
    }
    if rule_id.contains("kids.memory.victim_vulnerability_targeting") {
        return Some(EventKind::SuicidalIdeation);
    }
    if rule_id.contains("kids.memory.bullying_cascade_selfharm") {
        return Some(EventKind::SuicidalIdeation);
    }
    if rule_id.contains("military.opsec.coordinate_compound") {
        return Some(EventKind::CoordinateMention);
    }
    if rule_id.contains("military.psyops.social_eng_compound")
        || rule_id.contains("military.psyops.family_pressure")
    {
        return Some(EventKind::MilitaryDisinfo);
    }
    if rule_id.contains("military.social_eng.command_spoof") {
        return Some(EventKind::MilitaryPhishing);
    }

    if rule_id.contains("encourage_harm") {
        return Some(EventKind::HarmEncouragement);
    }
    if rule_id.contains("bodyshame") || rule_id.contains("dehumanize") || rule_id.contains("ugly") {
        return Some(EventKind::Denigration);
    }
    if rule_id.contains("exclusion")
        || rule_id.contains("you_dont_belong")
        || rule_id.contains("isolate_suggest")
    {
        return Some(EventKind::Exclusion);
    }
    if rule_id.contains("passive_agg") {
        return Some(EventKind::Mockery);
    }
    if rule_id.contains("bullying") && rule_id.contains("003") {
        return Some(EventKind::Exclusion);
    }
    if rule_id.contains("bullying") && rule_id.contains("002") {
        return Some(EventKind::Denigration);
    }
    if rule_id.contains("bullying") {
        return Some(EventKind::Insult);
    }

    if rule_id.starts_with("grooming_secrecy") {
        return Some(EventKind::SecrecyRequest);
    }
    if rule_id.starts_with("grooming_gifts") {
        return Some(EventKind::GiftOffer);
    }
    if rule_id.starts_with("grooming_meeting") {
        return Some(EventKind::MeetingRequest);
    }
    if rule_id.starts_with("grooming_age_probing") {
        return Some(EventKind::PersonalInfoRequest);
    }
    if rule_id.starts_with("grooming_flattery") {
        return Some(EventKind::Flattery);
    }
    if rule_id.starts_with("grooming_photo") {
        return Some(EventKind::PhotoRequest);
    }
    if rule_id.starts_with("grooming_platform_switch") {
        return Some(EventKind::PlatformSwitch);
    }
    if rule_id.starts_with("grooming_sexual") {
        return Some(EventKind::SexualContent);
    }
    if rule_id.starts_with("grooming_emotional_dependency") {
        return Some(EventKind::EmotionalBlackmail);
    }
    if rule_id.starts_with("grooming_video_call") {
        return Some(EventKind::VideoCallRequest);
    }
    if rule_id.starts_with("grooming_body_comment") {
        return Some(EventKind::SexualContent);
    }
    if rule_id.starts_with("grooming_location") {
        return Some(EventKind::LocationRequest);
    }
    if rule_id.starts_with("grooming_money") {
        return Some(EventKind::MoneyOffer);
    }
    if rule_id.starts_with("selfharm") && rule_id.contains("002") {
        return Some(EventKind::SuicidalIdeation);
    }
    if rule_id.starts_with("selfharm") {
        return Some(EventKind::Hopelessness);
    }
    if rule_id.starts_with("platform_switch_teen") {
        return Some(EventKind::PlatformSwitch);
    }
    if rule_id.starts_with("gaming_bribery") {
        return Some(EventKind::GiftOffer);
    }
    if rule_id.starts_with("emotional_withdrawal") {
        return Some(EventKind::Devaluation);
    }
    if rule_id.starts_with("manipulation_gaslighting") {
        return Some(EventKind::Gaslighting);
    }
    if rule_id.starts_with("manipulation_guilt") {
        return Some(EventKind::GuiltTripping);
    }
    if rule_id.starts_with("manipulation_pressure") {
        return Some(EventKind::PeerPressure);
    }
    if rule_id.starts_with("manipulation_isolation") {
        return Some(EventKind::Exclusion);
    }
    if rule_id.starts_with("manipulation_blackmail") || rule_id.starts_with("sextortion") {
        return Some(EventKind::EmotionalBlackmail);
    }
    if rule_id.starts_with("manipulation_darvo") {
        return Some(EventKind::Darvo);
    }
    if rule_id.starts_with("manipulation_intermittent") {
        return Some(EventKind::Devaluation);
    }
    if rule_id.starts_with("substance_") {
        return Some(EventKind::PeerPressure);
    }
    if rule_id.starts_with("coercion_suicide") {
        return Some(EventKind::SuicideCoercion);
    }
    if rule_id.starts_with("false_consensus") {
        return Some(EventKind::FalseConsensus);
    }
    if rule_id.starts_with("debt_creation") {
        return Some(EventKind::DebtCreation);
    }
    if rule_id.starts_with("reputation_threat") {
        return Some(EventKind::ReputationThreat);
    }
    if rule_id.starts_with("identity_erosion") {
        return Some(EventKind::IdentityErosion);
    }
    if rule_id.starts_with("network_poisoning") {
        return Some(EventKind::NetworkPoisoning);
    }
    if rule_id.starts_with("fake_vulnerability") {
        return Some(EventKind::FakeVulnerability);
    }
    if rule_id.starts_with("doxxing") {
        return Some(EventKind::DoxxingAttempt);
    }
    if rule_id.starts_with("screenshot_threat") {
        return Some(EventKind::ScreenshotThreat);
    }
    if rule_id.starts_with("hate_") {
        return Some(EventKind::HateSpeech);
    }
    if rule_id.starts_with("pii_") {
        return Some(EventKind::PiiSelfDisclosure);
    }
    if rule_id.starts_with("meeting_casual") {
        return Some(EventKind::CasualMeetingRequest);
    }
    if rule_id.starts_with("dare_") || rule_id.starts_with("dangerous_") {
        return Some(EventKind::DareChallenge);
    }

    if rule_id.starts_with("propaganda_domain_")
        || rule_id.starts_with("propaganda_telegram_channel_")
    {
        return Some(EventKind::SuspiciousSource);
    }
    if rule_id.contains("conversation.propaganda.suspicious_source")
        || rule_id.contains("conversation.propaganda.disinfo_source_blend")
    {
        return Some(EventKind::SuspiciousSource);
    }
    if rule_id.contains("conversation.propaganda.high_velocity")
        || rule_id.contains("conversation.propaganda.coordinated")
        || rule_id.contains("cross_conversation.propaganda.")
    {
        return Some(EventKind::PropagandaNarrative);
    }
    if rule_id.starts_with("opsec_coordinates_") {
        return Some(EventKind::CoordinateMention);
    }
    if rule_id.starts_with("opsec_movement_") {
        return Some(EventKind::PositionLeak);
    }
    if rule_id.starts_with("opsec_casualties_") || rule_id.starts_with("opsec_callsign_") {
        return Some(EventKind::UnitInfoLeak);
    }
    if rule_id.starts_with("opsec_equipment_") {
        return Some(EventKind::EquipmentLeak);
    }
    if rule_id.starts_with("military_phishing_") {
        return Some(EventKind::MilitaryPhishing);
    }
    if rule_id.starts_with("intel_") {
        return Some(EventKind::IntelGathering);
    }
    if rule_id.starts_with("psyops_fake_ceasefire_") {
        return Some(EventKind::MilitaryDisinfo);
    }
    None
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
    if let Some(kind) = map_domain_rule_to_event_kind(rule_id) {
        return Some(kind);
    }
    map_threat_to_event_kind(threat_type)
}

pub fn map_domain_signal_to_event_kind(threat_type: ThreatType) -> Option<EventKind> {
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
            | ThreatType::PiiLeakage => config.enabled,
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

pub fn merge_domain_output_effects(
    reason_codes: &mut Vec<String>,
    current_action: Action,
    domain_output: Option<&DomainOutput>,
) -> Action {
    let Some(domain_output) = domain_output else {
        return current_action;
    };

    push_domain_reason_codes(reason_codes, domain_output);

    let Some(action) = domain_output.action else {
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

pub fn build_domain_detection_signals(
    domain_output: Option<&DomainOutput>,
) -> Vec<DetectionSignal> {
    let Some(domain_output) = domain_output else {
        return Vec::new();
    };

    let mut signals = Vec::with_capacity(domain_output.signals.len());
    for signal in &domain_output.signals {
        let threat_type = domain_signal_threat_type(signal.threat_type.as_deref());
        if threat_type == ThreatType::None {
            continue;
        }

        let reason = if signal.reason_code.is_empty() {
            format!("domain.{}", signal.threat_key)
        } else {
            format!("domain.{}", signal.reason_code)
        };
        let confidence = domain_signal_confidence(signal.severity.as_deref(), signal.score);
        let signal = DetectionSignal::context(
            threat_type,
            signal.score,
            confidence,
            SignalFamily::Content,
            reason,
            "Domain module signal",
        )
        .with_threat_subtype(signal.threat_key.clone());
        signals.push(signal);
    }
    signals
}

pub fn build_domain_observations(
    domain_signals: Vec<DetectionSignal>,
    content_hash: Option<u64>,
) -> Vec<RawObservation> {
    let mut observations = Vec::with_capacity(domain_signals.len());
    for signal in domain_signals {
        let kind_from_reason = map_domain_rule_to_event_kind(&signal.reason_code);
        let kind_from_subtype = map_domain_rule_to_event_kind(&signal.threat_subtype);
        let kind = match (kind_from_reason, kind_from_subtype) {
            (Some(kind), _) => Some(kind),
            (None, Some(kind)) => Some(kind),
            (None, None) => map_domain_signal_to_event_kind(signal.threat_type),
        };
        let subtype = if signal.threat_subtype.is_empty() {
            None
        } else {
            Some(signal.threat_subtype.clone())
        };

        let observation = match kind {
            Some(kind) => {
                let score = signal.score;
                RawObservation::signal_with_event(signal, kind, score, subtype, content_hash)
            }
            None => RawObservation::signal(signal),
        };
        observations.push(observation);
    }
    observations
}

pub fn build_blocked_url_signal(blocked: &BlockedUrlMatch) -> DetectionSignal {
    let threat_type = parse_threat_type_label(&blocked.threat_type);
    let reason_code = blocked_url_reason_code(threat_type, &blocked.rule_id);
    let explanation = format!("{}: {}", blocked.explanation, blocked.url);
    let threat_subtype =
        map_domain_threat_subtype(&blocked.rule_id, threat_type, Some(&blocked.url));

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

pub fn should_skip_domain_rule_override(rule_id: &str, matched_rule_ids: &HashSet<String>) -> bool {
    rule_id == "opsec_coordinates_001"
        && matched_rule_ids.contains("opsec_coordinates_ukraine_dd_001")
}

pub fn should_skip_domain_match(
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

    if rule_id == "opsec_coordinates_001" {
        let Some(matched_text) = matched_text else {
            return false;
        };
        if validate_ukraine_coordinates(matched_text).is_empty() {
            return true;
        }
    }
    false
}

pub fn map_domain_threat_subtype(
    rule_id: &str,
    threat_type: ThreatType,
    matched_text: Option<&str>,
) -> Option<String> {
    let subtype = match threat_type {
        ThreatType::Propaganda => NarrativeId::from_rule_id(rule_id)
            .map(|narrative| narrative.tag())
            .or_else(|| propaganda_source_subtype(rule_id)),
        ThreatType::Psyops => psyops_subtype(rule_id, matched_text),
        ThreatType::MilitarySocialEng => military_social_eng_subtype(rule_id),
        ThreatType::CoordinateLeak => coordinate_subtype(rule_id),
        ThreatType::OpsecViolation => opsec_subtype(rule_id),
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

fn psyops_subtype(rule_id: &str, matched_text: Option<&str>) -> Option<&'static str> {
    if rule_id.starts_with("psyops_surrender_") {
        if matched_text
            .map(|text| {
                let lower = text.to_lowercase();
                lower.contains("волга") || lower.contains("volga")
            })
            .unwrap_or(false)
        {
            Some("surrender_volga")
        } else {
            Some("surrender")
        }
    } else if rule_id.starts_with("psyops_distrust_") {
        Some("command_distrust")
    } else if rule_id.starts_with("psyops_family_target_") {
        Some("family_targeting")
    } else if rule_id.starts_with("psyops_division_regional_") {
        Some("regional_division")
    } else if rule_id.starts_with("psyops_command_distrust_") {
        Some("command_distrust")
    } else if rule_id.starts_with("psyops_fake_ceasefire_") {
        Some("fake_ceasefire")
    } else if rule_id.starts_with("psyops_demoralize_direct_") {
        Some("demoralization")
    } else {
        None
    }
}

fn military_social_eng_subtype(rule_id: &str) -> Option<&'static str> {
    if rule_id.starts_with("military_phishing_diia_") {
        Some("phishing_diia")
    } else if rule_id.starts_with("military_phishing_tck_") {
        Some("phishing_tck")
    } else if rule_id.starts_with("military_phishing_delta_") {
        Some("phishing_delta")
    } else if rule_id.starts_with("military_phishing_command_") {
        Some("phishing_command")
    } else if rule_id.starts_with("military_phishing_account_") {
        Some("phishing_account")
    } else if rule_id.starts_with("intel_honeytrap_") {
        Some("honeytrap")
    } else if rule_id.starts_with("military_phishing_") {
        Some("military_phishing")
    } else {
        None
    }
}

fn coordinate_subtype(rule_id: &str) -> Option<&'static str> {
    if rule_id.starts_with("opsec_coordinates_w3w_") {
        Some("w3w")
    } else if rule_id.starts_with("opsec_coordinates_google_maps_") {
        Some("google_maps")
    } else if rule_id.starts_with("opsec_coordinates_ukraine_dd_") {
        Some("ukraine_dd")
    } else if rule_id.starts_with("opsec_coordinates_milgrid_") {
        Some("milgrid")
    } else if rule_id.starts_with("opsec_coordinates_mgrs_") {
        Some("mgrs")
    } else if rule_id.starts_with("opsec_coordinates_pluscode_") {
        Some("pluscode")
    } else {
        None
    }
}

fn opsec_subtype(rule_id: &str) -> Option<&'static str> {
    if rule_id.starts_with("opsec_movement_") {
        Some("movement")
    } else if rule_id.starts_with("opsec_casualties_") {
        Some("casualties")
    } else if rule_id.starts_with("opsec_equipment_") {
        Some("equipment")
    } else if rule_id.starts_with("opsec_callsign_") {
        Some("callsign")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_blocked_url_signal, build_domain_detection_signals, build_domain_observations,
        core_action_from_domain_action, decide_action_with_domain_overrides,
        detection_enabled_for_threat, domain_action_reason_marker, domain_conversation_type,
        domain_risk_profile_for_mode, domain_signal_confidence, domain_signal_threat_type,
        domain_threat_priority, is_domain_threat, is_link_family_threat, is_propaganda_threat,
        map_domain_rule_to_event_kind, map_domain_signal_to_event_kind, map_domain_threat_subtype,
        map_domain_threat_to_event_kind, map_ml_signal_to_event_kind,
        map_rule_or_threat_to_event_kind, map_threat_to_event_kind, merge_domain_output_effects,
        parse_domain_threat_type, parse_threat_type_label, should_skip_domain_match,
        should_skip_domain_rule_override, threat_priority_for_sort,
    };
    use crate::context::events::EventKind;
    use crate::ids::{ConversationId, SenderId};
    use crate::types::{Action, ContentType, ConversationType, ProtectionLevel, ThreatType};
    use crate::{AuraConfig, AuraDomainRuntime, DomainMode, MessageInput};
    use aura_domain::{DomainAction, DomainOutput, DomainSignal};
    use aura_patterns::BlockedUrlMatch;
    use std::collections::HashSet;

    #[test]
    fn military_rule_mapping_works() {
        assert_eq!(
            map_domain_rule_to_event_kind("military_phishing_diia_001"),
            Some(EventKind::MilitaryPhishing)
        );
        assert_eq!(
            map_domain_rule_to_event_kind("opsec_coordinates_uk_001"),
            Some(EventKind::CoordinateMention)
        );
        assert_eq!(
            map_domain_rule_to_event_kind("propaganda_domain_state_001"),
            Some(EventKind::SuspiciousSource)
        );
        assert_eq!(
            map_domain_rule_to_event_kind("grooming_secrecy_boundary_001"),
            Some(EventKind::SecrecyRequest)
        );
        assert_eq!(
            map_domain_rule_to_event_kind("selfharm_acute_002"),
            Some(EventKind::SuicidalIdeation)
        );
        assert_eq!(
            map_domain_rule_to_event_kind("selfharm_acute_001"),
            Some(EventKind::Hopelessness)
        );
        assert_eq!(
            map_domain_rule_to_event_kind("platform_switch_teen_001"),
            Some(EventKind::PlatformSwitch)
        );
        assert_eq!(
            map_domain_rule_to_event_kind("manipulation_gaslighting_001"),
            Some(EventKind::Gaslighting)
        );
        assert_eq!(
            map_domain_rule_to_event_kind("coercion_suicide_001"),
            Some(EventKind::SuicideCoercion)
        );
        assert_eq!(
            map_domain_rule_to_event_kind("kids.manipulation.image_sextortion"),
            Some(EventKind::ScreenshotThreat)
        );
        assert_eq!(
            map_domain_rule_to_event_kind("kids.memory.grooming_progression"),
            Some(EventKind::SecrecyRequest)
        );
        assert_eq!(
            map_domain_rule_to_event_kind("kids.memory.sender_risk_accumulation"),
            Some(EventKind::EmotionalBlackmail)
        );
        assert_eq!(
            map_domain_rule_to_event_kind("kids.memory.new_sender_fast_escalation"),
            Some(EventKind::EmotionalBlackmail)
        );
        assert_eq!(
            map_domain_rule_to_event_kind("kids.memory.cross_conversation_repeat_offender"),
            Some(EventKind::EmotionalBlackmail)
        );
        assert_eq!(
            map_domain_rule_to_event_kind("kids.memory.victim_vulnerability_targeting"),
            Some(EventKind::SuicidalIdeation)
        );
        assert_eq!(
            map_domain_rule_to_event_kind("kids.memory.bullying_cascade_selfharm"),
            Some(EventKind::SuicidalIdeation)
        );
        assert_eq!(
            map_domain_rule_to_event_kind("identity_erosion_001"),
            Some(EventKind::IdentityErosion)
        );
        assert_eq!(
            map_domain_rule_to_event_kind("bullying_pattern_003"),
            Some(EventKind::Exclusion)
        );
        assert_eq!(
            map_domain_rule_to_event_kind("doxxing_001"),
            Some(EventKind::DoxxingAttempt)
        );
        assert_eq!(
            map_domain_rule_to_event_kind("hate_001"),
            Some(EventKind::HateSpeech)
        );
        assert_eq!(
            map_domain_rule_to_event_kind("pii_001"),
            Some(EventKind::PiiSelfDisclosure)
        );
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
            map_domain_signal_to_event_kind(ThreatType::Manipulation),
            Some(EventKind::GuiltTripping)
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
        let mut config = AuraConfig::default();
        config.enabled = false;
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

        let domain_output = DomainOutput {
            signals: vec![DomainSignal {
                threat_key: "grooming.secrecy".to_string(),
                reason_code: "kids.grooming.secrecy".to_string(),
                score: 0.91,
                severity: Some("high".to_string()),
                priority: Some(95),
                action: None,
                threat_type: Some("grooming".to_string()),
            }],
            action: None,
        };
        let signals = build_domain_detection_signals(Some(&domain_output));
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].threat_type, ThreatType::Grooming);
        let observations = build_domain_observations(signals, Some(42));
        assert_eq!(observations.len(), 1);
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
    fn military_subtype_mapping_works() {
        assert_eq!(
            map_domain_threat_subtype(
                "military_phishing_diia_001",
                ThreatType::MilitarySocialEng,
                None,
            ),
            Some("phishing_diia".to_string())
        );
        assert_eq!(
            map_domain_threat_subtype(
                "opsec_coordinates_ukraine_dd_001",
                ThreatType::CoordinateLeak,
                None,
            ),
            Some("ukraine_dd".to_string())
        );
        assert_eq!(
            map_domain_threat_subtype(
                "psyops_surrender_001",
                ThreatType::Psyops,
                Some("Скажи Волга"),
            ),
            Some("surrender_volga".to_string())
        );
        assert_eq!(
            map_domain_threat_subtype("propaganda_domain_state_001", ThreatType::Propaganda, None),
            Some("state_media".to_string())
        );
    }

    #[test]
    fn skips_generic_coordinate_rule_outside_ukraine() {
        assert!(should_skip_domain_match(
            "55.7558, 37.6173",
            ThreatType::CoordinateLeak,
            "opsec_coordinates_001",
            Some("55.7558, 37.6173"),
        ));
        assert!(!should_skip_domain_match(
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
        assert!(should_skip_domain_rule_override(
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
            server_sender_risk_hint: None,
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
            server_sender_risk_hint: None,
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
