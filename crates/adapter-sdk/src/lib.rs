//! Shared, replayable contracts for language investigation adapters.

use std::sync::Arc;

use async_trait::async_trait;
use edsa_core::{EvidenceAssessment, EvidenceId, EvidenceRef, OracleKind, SCHEMA_VERSION, Verdict};
use edsa_sandbox::docker::SandboxError;
use edsa_sandbox::{DockerRunner, SandboxOutput, SandboxRequest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Oracle {
    pub kind: OracleKind,
    pub expected: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentRequest {
    pub sandbox: SandboxRequest,
    pub oracle: Oracle,
    pub negative_control: Oracle,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordedExecution {
    pub command: Vec<String>,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

impl From<SandboxOutput> for RecordedExecution {
    fn from(output: SandboxOutput) -> Self {
        Self {
            command: Vec::new(),
            exit_code: output.exit_code,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            stdout_truncated: output.stdout_truncated,
            stderr_truncated: output.stderr_truncated,
        }
    }
}

#[async_trait]
pub trait SandboxBackend: std::fmt::Debug + Send + Sync {
    /// Runs an adapter request inside its execution boundary.
    async fn run(
        &self,
        request: SandboxRequest,
        cancellation: CancellationToken,
    ) -> Result<SandboxOutput, SandboxError>;
}

#[async_trait]
impl SandboxBackend for DockerRunner {
    async fn run(
        &self,
        request: SandboxRequest,
        cancellation: CancellationToken,
    ) -> Result<SandboxOutput, SandboxError> {
        DockerRunner::run(self, request, cancellation).await
    }
}

#[derive(Clone, Debug)]
pub struct ExperimentRunner {
    backend: Arc<dyn SandboxBackend>,
}

impl ExperimentRunner {
    #[must_use]
    pub fn new(backend: Arc<dyn SandboxBackend>) -> Self {
        Self { backend }
    }

    /// Runs a repository's ordinary regression suite once inside the sandbox.
    ///
    /// # Errors
    /// Returns an error if sandbox execution fails.
    pub async fn baseline(
        &self,
        request: SandboxRequest,
        oracle: &Oracle,
        cancellation: CancellationToken,
    ) -> Result<(RecordedExecution, bool), AdapterError> {
        let command = request.command.clone();
        let mut execution = RecordedExecution::from(self.backend.run(request, cancellation).await?);
        execution.command = command;
        let passed = evaluate(oracle, &execution);
        Ok((execution, passed))
    }

    /// Executes an experiment and its negative control in separate sandboxes.
    ///
    /// # Errors
    /// Returns an error if either sandbox execution fails.
    pub async fn execute(
        &self,
        experiment: ExperimentRequest,
        cancellation: CancellationToken,
    ) -> Result<ExperimentEvidence, AdapterError> {
        let mut attack = RecordedExecution::from(
            self.backend
                .run(experiment.sandbox.clone(), cancellation.clone())
                .await?,
        );
        attack.command.clone_from(&experiment.sandbox.command);
        let mut control_request = experiment.sandbox;
        control_request
            .environment
            .insert("EDSA_NEGATIVE_CONTROL".into(), "1".into());
        let mut control = RecordedExecution::from(
            self.backend
                .run(control_request.clone(), cancellation)
                .await?,
        );
        control.command = control_request.command;
        let oracle_passed = evaluate(&experiment.oracle, &attack);
        let negative_control_passed = evaluate(&experiment.negative_control, &control);
        Ok(ExperimentEvidence {
            attack,
            control,
            oracle_passed,
            negative_control_passed,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExperimentEvidence {
    pub attack: RecordedExecution,
    pub control: RecordedExecution,
    pub oracle_passed: bool,
    pub negative_control_passed: bool,
}

impl ExperimentEvidence {
    /// Returns the canonical bytes stored for this execution pair.
    ///
    /// # Errors
    /// Returns a JSON error if the execution record cannot be serialized.
    pub fn artifact_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    #[must_use]
    pub fn assessment(&self, baseline_passed: bool) -> EvidenceAssessment {
        let bytes = format!("{self:?}").into_bytes();
        let digest = format!("{:x}", Sha256::digest(&bytes));
        EvidenceAssessment {
            schema_version: SCHEMA_VERSION,
            baseline_passed,
            oracle_passed: self.oracle_passed,
            negative_control_passed: self.negative_control_passed,
            reproduced_runs: 1,
            evidence: vec![EvidenceRef {
                schema_version: SCHEMA_VERSION,
                id: EvidenceId::new(format!("evidence-{digest}")),
                media_type: "application/vnd.edsa.execution+json".into(),
                sha256: digest,
                size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            }],
        }
    }
}

#[must_use]
pub fn evaluate(oracle: &Oracle, execution: &RecordedExecution) -> bool {
    if execution.stdout_truncated || execution.stderr_truncated {
        return false;
    }
    match oracle.kind {
        OracleKind::ExitCode => execution.exit_code == oracle.expected.parse().ok(),
        OracleKind::StdoutPattern => execution.stdout.contains(&oracle.expected),
        OracleKind::StderrPattern => execution.stderr.contains(&oracle.expected),
        OracleKind::TestAssertion => {
            execution.exit_code == Some(0) && execution.stdout.contains(&oracle.expected)
        }
        OracleKind::FileSystemBoundary | OracleKind::NetworkCallback => {
            execution.stdout.contains(&oracle.expected)
        }
    }
}

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("sandbox execution failed: {0}")]
    Sandbox(#[from] SandboxError),
}

#[must_use]
pub fn classify(
    policy: &edsa_core::ConfirmationPolicy,
    evidence: &ExperimentEvidence,
    baseline_passed: bool,
) -> Verdict {
    policy.verdict(&evidence.assessment(baseline_passed))
}
