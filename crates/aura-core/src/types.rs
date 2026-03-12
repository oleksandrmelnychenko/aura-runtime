use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatType {
    None,
    Bullying,
    Grooming,
    Explicit,
    Threat,
    SelfHarm,
    Spam,
    Scam,
    Phishing,
    Manipulation,
    Nsfw,
    HateSpeech,
    Doxxing,
    PiiLeakage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Mark,
    Blur,
    Warn,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionLevel {
    Off,
    Low,
    #[default]
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountType {
    Adult,
    Teen,
    Child,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionLayer {
    PatternMatching,
    MlClassification,
    ContextAnalysis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SignalFamily {
    #[default]
    Content,
    Conversation,
    Link,
    Abuse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UiAction {
    WarnBeforeSend,
    WarnBeforeDisplay,
    BlurUntilTap,
    ConfirmBeforeOpenLink,
    SuggestBlockContact,
    SuggestReport,
    RestrictUnknownContact,
    SlowDownConversation,
    ShowCrisisSupport,
    EscalateToGuardian,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CircleTier {
    Inner,
    Regular,
    Occasional,
    #[default]
    New,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BehavioralTrend {
    #[default]
    Stable,
    Improving,
    GradualWorsening,
    RapidWorsening,
    RoleReversal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionSignal {
    pub threat_type: ThreatType,
    pub score: f32,
    pub confidence: Confidence,
    pub layer: DetectionLayer,
    #[serde(default)]
    pub family: SignalFamily,
    #[serde(default)]
    pub reason_code: String,
    pub explanation: String,
}

impl DetectionSignal {
    pub fn pattern(
        threat_type: ThreatType,
        score: f32,
        confidence: Confidence,
        reason_code: impl Into<String>,
        explanation: impl Into<String>,
    ) -> Self {
        let family = match threat_type {
            ThreatType::Phishing => SignalFamily::Link,
            ThreatType::Spam | ThreatType::Scam => SignalFamily::Abuse,
            _ => SignalFamily::Content,
        };

        Self {
            threat_type,
            score,
            confidence,
            layer: DetectionLayer::PatternMatching,
            family,
            reason_code: reason_code.into(),
            explanation: explanation.into(),
        }
    }

    pub fn ml(
        threat_type: ThreatType,
        score: f32,
        confidence: Confidence,
        reason_code: impl Into<String>,
        explanation: impl Into<String>,
    ) -> Self {
        Self {
            threat_type,
            score,
            confidence,
            layer: DetectionLayer::MlClassification,
            family: SignalFamily::Content,
            reason_code: reason_code.into(),
            explanation: explanation.into(),
        }
    }

    pub fn context(
        threat_type: ThreatType,
        score: f32,
        confidence: Confidence,
        family: SignalFamily,
        reason_code: impl Into<String>,
        explanation: impl Into<String>,
    ) -> Self {
        Self {
            threat_type,
            score,
            confidence,
            layer: DetectionLayer::ContextAnalysis,
            family,
            reason_code: reason_code.into(),
            explanation: explanation.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RiskBreakdown {
    pub content: f32,
    pub conversation: f32,
    pub link: f32,
    pub abuse: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UncertaintyLevel {
    Low,
    #[default]
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RiskHorizon {
    #[default]
    Unknown,
    Immediate,
    ShortTerm,
    Sustained,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LatentStateKind {
    DependencyBuilding,
    IsolationPressure,
    CoerciveControl,
    Humiliation,
    CrisisVulnerability,
    ProtectiveSupport,
    GroupEscalation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LatentStateEvidence {
    pub kind: LatentStateKind,
    pub score: f32,
    #[serde(default)]
    pub reason_codes: Vec<String>,
}

/// Internal modeling output for psychological inference.
/// This is intentionally domain-only and does not define the external protobuf contract.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct InferenceSummary {
    pub uncertainty: UncertaintyLevel,
    pub risk_horizon: RiskHorizon,
    pub escalation_likelihood_24h: f32,
    pub protective_factor_strength: f32,
    #[serde(default)]
    pub latent_states: Vec<LatentStateEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactSnapshot {
    pub sender_id: String,
    pub rating: f32,
    pub trust_level: f32,
    pub circle_tier: CircleTier,
    pub trend: BehavioralTrend,
    pub is_trusted: bool,
    pub is_new_contact: bool,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub conversation_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub threat_type: ThreatType,
    pub confidence: Confidence,
    pub action: Action,
    pub score: f32,
    pub explanation: String,
    pub detected_threats: Vec<(ThreatType, f32)>,
    pub signals: Vec<DetectionSignal>,
    pub recommended_action: Option<ActionRecommendation>,
    #[serde(default)]
    pub risk_breakdown: RiskBreakdown,
    #[serde(default)]
    pub contact_snapshot: Option<ContactSnapshot>,
    #[serde(default)]
    pub reason_codes: Vec<String>,
    #[serde(default)]
    pub inference: InferenceSummary,
    pub analysis_time_us: u64,
}

impl AnalysisResult {
    pub fn clean(analysis_time_us: u64) -> Self {
        Self {
            threat_type: ThreatType::None,
            confidence: Confidence::Low,
            action: Action::Allow,
            score: 0.0,
            explanation: String::new(),
            detected_threats: Vec::new(),
            signals: Vec::new(),
            recommended_action: None,
            risk_breakdown: RiskBreakdown::default(),
            contact_snapshot: None,
            reason_codes: Vec::new(),
            inference: InferenceSummary::default(),
            analysis_time_us,
        }
    }

    pub fn is_threat(&self) -> bool {
        self.threat_type != ThreatType::None
    }

    pub fn needs_crisis_resources(&self) -> bool {
        self.threat_type == ThreatType::SelfHarm
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertPriority {
    None,
    Low,
    Medium,
    High,
    Urgent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FollowUpAction {
    MonitorConversation,
    BlockSuggested,
    ReviewContactProfile,
    ReportToAuthorities,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRecommendation {
    pub parent_alert: AlertPriority,
    pub follow_ups: Vec<FollowUpAction>,
    pub crisis_resources: bool,
    #[serde(default)]
    pub ui_actions: Vec<UiAction>,
    #[serde(default)]
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConversationType {
    #[default]
    Direct,
    GroupChat,
    Group,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    Text,
    Image,
    Voice,
    Video,
    Url,
}

#[derive(Debug, Clone)]
pub struct MessageInput {
    pub content_type: ContentType,
    pub text: Option<String>,
    pub image_data: Option<Vec<u8>>,
    pub sender_id: String,
    pub conversation_id: String,
    pub language: Option<String>,
    pub conversation_type: ConversationType,
    pub member_count: Option<u32>,
}
