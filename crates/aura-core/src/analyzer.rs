//! Public analysis façade.
//!
//! The orchestration pipeline and its private stages live below this module so
//! callers keep the stable [`Analyzer`] path while implementation ownership
//! remains explicit.

mod orchestrator;

pub use orchestrator::Analyzer;
