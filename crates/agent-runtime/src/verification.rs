use std::path::Path;

use async_trait::async_trait;
use edsa_core::{GateOutcome, PatchGate, PatchGateEvidence, PatchVerification, SCHEMA_VERSION};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateExecution {
    pub command: Vec<String>,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl GateExecution {
    #[must_use]
    pub const fn passed(&self) -> bool {
        matches!(self.exit_code, Some(0))
    }
}

#[async_trait]
pub trait PatchGateExecutor: std::fmt::Debug + Send + Sync {
    /// Executes one deterministic gate inside the disposable worktree.
    async fn execute(
        &self,
        worktree: &Path,
        gate: PatchGate,
        variant_index: Option<u32>,
        cancellation: CancellationToken,
    ) -> GateExecution;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationPolicy {
    pub maximum_variant_cases: u32,
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self {
            maximum_variant_cases: 8,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LadderResult {
    pub evidence: Vec<PatchGateEvidence>,
    pub verification: PatchVerification,
    pub cancelled: bool,
}

#[derive(Debug)]
pub struct VerificationLadder<E> {
    executor: E,
    policy: VerificationPolicy,
}

impl<E: PatchGateExecutor> VerificationLadder<E> {
    /// Creates a verification ladder with a nonzero bounded variant search.
    ///
    /// # Errors
    /// Returns an error when the variant bound is zero.
    pub fn new(executor: E, policy: VerificationPolicy) -> Result<Self, VerificationError> {
        if policy.maximum_variant_cases == 0 {
            return Err(VerificationError::EmptyVariantSearch);
        }
        Ok(Self { executor, policy })
    }

    pub async fn run(&self, worktree: &Path, cancellation: &CancellationToken) -> LadderResult {
        let mut evidence = Vec::new();
        for gate in [
            PatchGate::BuildBaseline,
            PatchGate::OriginalProofStopped,
            PatchGate::NegativeControl,
            PatchGate::Regression,
            PatchGate::StaticRescan,
        ] {
            if cancellation.is_cancelled() {
                return result(evidence, true);
            }
            let execution = self
                .executor
                .execute(worktree, gate, None, cancellation.clone())
                .await;
            let passed = execution.passed();
            evidence.push(to_evidence(gate, None, execution));
            if !passed {
                return result(evidence, false);
            }
        }
        for index in 0..self.policy.maximum_variant_cases {
            if cancellation.is_cancelled() {
                return result(evidence, true);
            }
            let execution = self
                .executor
                .execute(
                    worktree,
                    PatchGate::VariantSearch,
                    Some(index),
                    cancellation.clone(),
                )
                .await;
            let passed = execution.passed();
            evidence.push(to_evidence(
                PatchGate::VariantSearch,
                Some(index),
                execution,
            ));
            if !passed {
                return result(evidence, false);
            }
        }
        result(evidence, false)
    }
}

fn to_evidence(
    gate: PatchGate,
    variant_index: Option<u32>,
    execution: GateExecution,
) -> PatchGateEvidence {
    let outcome = if execution.passed() {
        GateOutcome::Passed
    } else {
        GateOutcome::Failed
    };
    let summary = if execution.passed() {
        "gate passed"
    } else {
        "gate failed"
    };
    PatchGateEvidence {
        schema_version: SCHEMA_VERSION,
        gate,
        variant_index,
        outcome,
        command: execution.command,
        exit_code: execution.exit_code,
        stdout_sha256: format!("{:x}", Sha256::digest(&execution.stdout)),
        stderr_sha256: format!("{:x}", Sha256::digest(&execution.stderr)),
        summary: summary.into(),
    }
}

fn result(evidence: Vec<PatchGateEvidence>, cancelled: bool) -> LadderResult {
    let passed = |gate| {
        evidence
            .iter()
            .any(|item| item.gate == gate && item.outcome == GateOutcome::Passed)
    };
    let variants = evidence
        .iter()
        .filter(|item| item.gate == PatchGate::VariantSearch)
        .collect::<Vec<_>>();
    let variant_search = if !variants.is_empty()
        && variants
            .iter()
            .all(|item| item.outcome == GateOutcome::Passed)
        && !cancelled
    {
        GateOutcome::Passed
    } else {
        GateOutcome::Failed
    };
    LadderResult {
        verification: PatchVerification {
            schema_version: SCHEMA_VERSION,
            build: outcome(passed(PatchGate::BuildBaseline)),
            original_proof_stopped: outcome(passed(PatchGate::OriginalProofStopped)),
            negative_control: outcome(passed(PatchGate::NegativeControl)),
            regression_suite: outcome(passed(PatchGate::Regression)),
            static_rescan: outcome(passed(PatchGate::StaticRescan)),
            variant_search,
        },
        evidence,
        cancelled,
    }
}

const fn outcome(passed: bool) -> GateOutcome {
    if passed {
        GateOutcome::Passed
    } else {
        GateOutcome::Failed
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum VerificationError {
    #[error("variant search must execute at least one bounded case")]
    EmptyVariantSearch,
}
