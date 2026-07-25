//! Contact-level context memory façade.
//!
//! Public contact state remains available from this module while the
//! relationship and trajectory implementation is owned by a private module.

mod relationship;

pub use relationship::{
    AgeSource, BehavioralSnapshot, BehavioralSnapshotState, ChildSafetyTrajectory, ContactProfile,
    ContactProfileState, ContactProfiler, ContactProfilerState, ContactProfilerWireState,
    DEFAULT_MAX_CONTACT_PROFILES,
};
