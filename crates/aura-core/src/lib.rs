//! Core analysis engine for the AURA intelligent protection system.
//!
//! The current implementation is split across:
//!
//! - `aura-contracts` — canonical shared types (ThreatType, Confidence, etc.)
//! - `aura-agent-core` — on-device runtime orchestration
//! - `aura-agent-policy` — action decisions, product surfacing, shadow/pilot
//! - `aura-relay-*` — server-side inference and intelligence
//!
//! `aura-core` owns the analyzer, domain context, and evaluation implementation.
//! Cross-boundary contracts and runtime orchestration belong to their dedicated
//! crates.
//!
//! ## Module ownership
//!
//! | Module | Target crate |
//! |---|---|
//! | `types` (shared enums) | `aura-contracts` |
//! | `action`, `product`, `pilot`, `pilot_gate` | `aura-agent-policy` |
//! | `analyzer`, `context`, `domain_runtime` | `aura-agent-core` |
//! | `audit` | shared or agent-policy |
//! | `config`, `ids`, `error` | `aura-contracts` or `aura-agent-core` |
//! | `eval*`, `dataset_manifest` | `aura-core` |

pub mod action;
pub mod analyzer;
pub mod audit;
pub mod config;
pub mod context;
pub mod dataset_manifest;
pub mod domain_runtime;
pub mod error;
pub mod eval;
pub mod eval_corpus;
pub mod eval_external;
pub mod eval_policy;
pub mod eval_realistic;
pub mod eval_release;
pub mod eval_robustness;
pub mod eval_scenarios;
pub mod eval_simulation_regression;
pub mod eval_social_context;
pub mod ids;
pub mod pilot;
pub mod pilot_gate;
pub mod product;
pub mod runtime_capabilities;
pub mod scenario_packs;
pub mod types;

pub use analyzer::Analyzer;
pub use audit::*;
pub use config::AuraConfig;
pub use context::ConversationTracker;
pub use dataset_manifest::*;
pub use domain_runtime::AuraDomainRuntime;
pub use error::AuraError;
pub use eval::*;
pub use eval_corpus::*;
pub use eval_external::*;
pub use eval_policy::*;
pub use eval_realistic::*;
pub use eval_release::*;
pub use eval_robustness::*;
pub use eval_scenarios::*;
pub use eval_simulation_regression::*;
pub use eval_social_context::*;
pub use ids::*;
pub use pilot::*;
pub use pilot_gate::*;
pub use product::*;
pub use runtime_capabilities::*;
pub use types::*;
