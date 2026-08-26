use serde::{Deserialize, Serialize};

use crate::{GateOutcome, PatchAttemptId, PatchVerification, SCHEMA_VERSION};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchGate {
    BuildBaseline,
    OriginalProofStopped,
    NegativeControl,
    Regression,
    StaticRescan,
    VariantSearch,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PatchGateEvidence {
    pub schema_version: u16,
    pub gate: PatchGate,
    pub variant_index: Option<u32>,
    pub outcome: GateOutcome,
    pub command: Vec<String>,
    pub exit_code: Option<i32>,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub summary: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchAttemptStatus {
    Verified,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PatchAttemptRecord {
    pub schema_version: u16,
    pub id: PatchAttemptId,
    pub patch_sha256: String,
    pub status: PatchAttemptStatus,
    pub gates: Vec<PatchGateEvidence>,
    pub verification: PatchVerification,
}

impl PatchAttemptRecord {
    #[must_use]
    pub fn new(
        id: PatchAttemptId,
        patch_sha256: String,
        status: PatchAttemptStatus,
        gates: Vec<PatchGateEvidence>,
        verification: PatchVerification,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            id,
            patch_sha256,
            status,
            gates,
            verification,
        }
    }
}
