//! Stable C FFI façade for the AURA analysis engine.
//!
//! Exported symbol names remain rooted here through re-exports while lifecycle,
//! protobuf conversion, state, buffer, and policy implementation stay private.

#![allow(clippy::missing_safety_doc)]

mod execution_policy;
mod lifecycle;

pub use lifecycle::*;
