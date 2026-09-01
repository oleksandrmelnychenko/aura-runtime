//! Shared, domain-neutral contracts for AURA safety modules.
//!
//! The crate owns module registration, bounded inputs and outputs, lexical rule
//! validation, monotonic action policy, and content-free temporal projections.
//! Domain-specific detectors remain in `aura-kids` and `aura-military`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Stable cryptographic evidence for bundled domain policy packs.
pub mod evidence;
/// Bounded message-level inputs and model hints.
pub mod input;
/// Typed language and script evidence for multilingual detector routing.
pub mod language;
/// Lexical rule representation, matching, and validation.
pub mod lexical;
/// Domain module identity and execution trait.
pub mod module;
/// Domain signals, actions, and typed event routing.
pub mod output;
/// Shared monotonic action policy.
pub mod policy;
/// Runtime module registry.
pub mod registry;
/// Preregistered, policy-bound contracts for independent domain evaluation.
pub mod research;
/// Signed evidence for one independent aggregate recomputation attempt.
pub mod research_recomputation;
/// Append-only registry evidence for submitted recomputation attempts.
pub mod research_recomputation_registry;
/// Private materialization contract for independently reproducible studies.
pub mod research_reproduction;
/// Signed, timestamped result evidence for independent domain evaluation.
pub mod research_result;
/// Bounded structural evidence for compositional context interpretation.
pub mod semantic;
/// Content-free temporal projection contracts.
pub mod temporal;

pub use evidence::*;
pub use input::*;
pub use language::*;
pub use lexical::*;
pub use module::*;
pub use output::*;
pub use policy::*;
pub use registry::*;
pub use research::*;
pub use research_recomputation::*;
pub use research_recomputation_registry::*;
pub use research_reproduction::*;
pub use research_result::*;
pub use semantic::*;
pub use temporal::*;
