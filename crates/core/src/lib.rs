//! Stable domain records and deterministic lifecycle rules.
//!
//! Language models may propose hypotheses and experiments, but only this crate's
//! typed policies and state transitions can assign verdicts or verify patches.

pub mod language;
pub mod model;
pub mod patch;
pub mod policy;
pub mod repository;
pub mod state;

pub use language::*;
pub use model::*;
pub use patch::*;
pub use policy::*;
pub use repository::*;
pub use state::*;

/// Schema version shared by the first generation of domain records.
pub const SCHEMA_VERSION: u16 = 1;
