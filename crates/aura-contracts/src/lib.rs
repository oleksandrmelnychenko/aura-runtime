//! Shared typed contracts for the AURA on-device runtime.

pub mod common;
pub mod context;
pub mod event;
pub mod observation;

pub use common::{
    AccountType, Confidence, ConversationType, DetectionLayer, ProtectionLevel,
    RelationshipTrustSource, SenderRelationship, ThreatType,
};
pub use context::{
    Directionality, RelationshipTag, SpeechAct, Stance, ThreatContextFrame, TrajectoryTag,
};
pub use event::ConfirmedEvent;
pub use observation::RawObservation;
