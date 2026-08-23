//! Stable domain records and deterministic lifecycle rules.
//!
//! Language models may propose hypotheses and experiments, but only this crate's
//! typed policies and state transitions can assign verdicts or verify patches.

pub mod model;
pub mod state;

pub use model::*;
pub use state::*;

/// Schema version shared by the first generation of domain records.
pub const SCHEMA_VERSION: u16 = 1;
