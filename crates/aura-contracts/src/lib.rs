//! Shared typed contracts for AURA Agent and AURA Relay.

pub mod common;
pub mod context;
pub mod event;
pub mod observation;
pub mod relay;

pub use common::{
    AccountType, Confidence, ConversationType, DetectionLayer, ProtectionLevel, ThreatType,
};
pub use context::{
    Directionality, RelationshipTag, SpeechAct, Stance, ThreatContextFrame, TrajectoryTag,
};
pub use event::ConfirmedEvent;
pub use observation::RawObservation;
pub use relay::{
    default_relay_schema_version, AgentAnalyzeRequest, AgentCapabilities, LocalContextSummary,
    MessageWindowEntry, RelayAnalyzeResponse, RelayPrivacyMode, RemoteFinding,
    RemoteInferenceSummary, RiskHorizon, AURA_RELAY_SCHEMA_VERSION,
};
