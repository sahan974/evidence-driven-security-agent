use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::SCHEMA_VERSION;

macro_rules! string_id {
    ($name:ident) => {
        #[doc = concat!("Stable identifier for a `", stringify!($name), "` record.")]
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            #[must_use]
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

string_id!(InvestigationId);
string_id!(SignalId);
string_id!(HypothesisId);
string_id!(ExperimentId);
string_id!(EvidenceId);
string_id!(PatchAttemptId);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepositorySnapshot {
    pub schema_version: u16,
    /// Portable path relative to the configured project root.
    pub repository_path: String,
    pub revision: String,
    pub content_digest: String,
    pub dirty: bool,
}

impl RepositorySnapshot {
    #[must_use]
    pub fn new(
        repository_path: impl Into<String>,
        revision: impl Into<String>,
        content_digest: impl Into<String>,
        dirty: bool,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            repository_path: repository_path.into(),
            revision: revision.into(),
            content_digest: content_digest.into(),
            dirty,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalSource {
    BuiltInRule,
    ExternalAnalyzer,
    ModelProposal,
    Human,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Signal {
    pub schema_version: u16,
    pub id: SignalId,
    pub source: SignalSource,
    pub rule: String,
    pub relative_path: String,
    pub start_line: u32,
    pub message: String,
    /// Sorted metadata avoids map-order differences across runs.
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Hypothesis {
    pub schema_version: u16,
    pub id: HypothesisId,
    pub title: String,
    pub claim: String,
    pub weakness: String,
    pub signal_ids: Vec<SignalId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleKind {
    ExitCode,
    StdoutPattern,
    StderrPattern,
    FileSystemBoundary,
    NetworkCallback,
    TestAssertion,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleContract {
    pub schema_version: u16,
    pub kind: OracleKind,
    pub expected: String,
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Experiment {
    pub schema_version: u16,
    pub id: ExperimentId,
    pub hypothesis_id: HypothesisId,
    pub description: String,
    pub command: Vec<String>,
    pub oracle: OracleContract,
    pub negative_control: Option<OracleContract>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceRef {
    pub schema_version: u16,
    pub id: EvidenceId,
    pub media_type: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Confirmed,
    Rejected,
    Inconclusive,
}

/// Deterministic evidence inputs used to assign a verdict.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceAssessment {
    pub schema_version: u16,
    pub baseline_passed: bool,
    pub oracle_passed: bool,
    pub negative_control_passed: bool,
    pub reproduced_runs: u16,
    pub evidence: Vec<EvidenceRef>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfirmationPolicy {
    pub schema_version: u16,
    pub minimum_reproductions: u16,
    pub minimum_evidence_items: usize,
    pub require_baseline: bool,
    pub require_negative_control: bool,
}

impl Default for ConfirmationPolicy {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            minimum_reproductions: 1,
            minimum_evidence_items: 1,
            require_baseline: true,
            require_negative_control: true,
        }
    }
}

impl ConfirmationPolicy {
    #[must_use]
    pub fn verdict(&self, assessment: &EvidenceAssessment) -> Verdict {
        let baseline_ok = !self.require_baseline || assessment.baseline_passed;
        let control_ok = !self.require_negative_control || assessment.negative_control_passed;
        let reproduced = assessment.reproduced_runs >= self.minimum_reproductions;
        let evidence_sufficient = assessment.evidence.len() >= self.minimum_evidence_items;

        if assessment.oracle_passed
            && baseline_ok
            && control_ok
            && reproduced
            && evidence_sufficient
        {
            Verdict::Confirmed
        } else if baseline_ok && control_ok && reproduced && !assessment.oracle_passed {
            Verdict::Rejected
        } else {
            Verdict::Inconclusive
        }
    }
}

/// Machine gates for a patch. This record deliberately contains no model opinion.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateOutcome {
    Passed,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PatchVerification {
    pub schema_version: u16,
    pub build: GateOutcome,
    pub original_proof_stopped: GateOutcome,
    pub negative_control: GateOutcome,
    pub regression_suite: GateOutcome,
    pub static_rescan: GateOutcome,
    pub variant_search: GateOutcome,
}

impl PatchVerification {
    #[must_use]
    pub const fn all_required_gates_pass(&self) -> bool {
        matches!(self.build, GateOutcome::Passed)
            && matches!(self.original_proof_stopped, GateOutcome::Passed)
            && matches!(self.negative_control, GateOutcome::Passed)
            && matches!(self.regression_suite, GateOutcome::Passed)
            && matches!(self.static_rescan, GateOutcome::Passed)
            && matches!(self.variant_search, GateOutcome::Passed)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PatchAttempt {
    pub schema_version: u16,
    pub id: PatchAttemptId,
    pub hypothesis_id: HypothesisId,
    pub diff_sha256: String,
    pub verification: Option<PatchVerification>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvestigationBudget {
    pub schema_version: u16,
    pub maximum_model_tokens: u64,
    pub maximum_experiments: u32,
    pub maximum_wall_time_seconds: u64,
    pub maximum_cost_microusd: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BudgetUsage {
    pub schema_version: u16,
    pub model_tokens: u64,
    pub experiments: u32,
    pub wall_time_seconds: u64,
    pub cost_microusd: u64,
}

impl Default for BudgetUsage {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            model_tokens: 0,
            experiments: 0,
            wall_time_seconds: 0,
            cost_microusd: 0,
        }
    }
}
