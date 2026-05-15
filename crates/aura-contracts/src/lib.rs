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
    default_relay_schema_version, sign_protected_account_token_attestation,
    sign_relay_request_auth, sign_relay_response_auth, verify_protected_account_token_attestation,
    verify_relay_request_auth, verify_relay_response_auth, AgentAnalyzeRequest, AgentCapabilities,
    ClientSafetyTelemetryEvent, LocalContextSummary, MessageWindowEntry,
    ProtectedAccountTokenAttestation, RelayAnalyzeResponse, RelayPrivacyMode, RelayRequestAuth,
    RelayResponseAuth, RemoteFinding, RemoteInferenceSummary, RiskHorizon, SafetyTelemetryAction,
    SafetyTelemetrySeverity, SafetyTelemetrySurface, AURA_RELAY_SCHEMA_VERSION,
    PROTECTED_ACCOUNT_TOKEN_ATTESTATION_ALG, RELAY_REQUEST_AUTH_ALG, RELAY_RESPONSE_AUTH_ALG,
};
