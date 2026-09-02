pub(crate) mod attribution;
pub mod coercion;
pub mod contact;
pub mod enricher;
pub mod events;
pub mod interpretation;
pub mod observation;
pub mod propaganda;
pub mod raid;
pub mod rules;
pub mod timing;
pub mod tracker;

pub use coercion::CoercionDetector;
pub use contact::ContactProfiler;
pub use enricher::SignalEnricher;
pub use events::{ContextEvent, EventKind};
pub use interpretation::{ConfirmedEvent, ContextInterpreter};
pub use propaganda::PropagandaDetector;
pub use raid::RaidDetector;
pub use rules::{
    builtin_context_rule_pack_evidence, ContextRuleError, ContextRulePackDigest,
    ContextRulePackEvidence,
};
pub use timing::TimingAnalyzer;
pub use tracker::ConversationTracker;
