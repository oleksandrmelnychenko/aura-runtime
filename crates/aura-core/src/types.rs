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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionSignal {
    pub threat_type: ThreatType,
    pub score: f32,
    pub confidence: Confidence,
    pub layer: DetectionLayer,
    pub explanation: String,
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
