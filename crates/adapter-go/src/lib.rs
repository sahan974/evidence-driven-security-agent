//! Go repository investigation adapter using native Go test tooling.

pub mod oracles;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use edsa_adapter_sdk::{
    ExperimentEvidence, ExperimentRequest, ExperimentRunner, Oracle, RecordedExecution,
};
use edsa_core::{Language, RepositoryInventory};
use edsa_evidence::{ArtifactError, ArtifactStore, StoredArtifact};
use edsa_sandbox::{SandboxPolicy, SandboxRequest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GoEnvironmentPlan {
    pub image: String,
    pub module_file: String,
    pub sum_file: Option<String>,
    pub locked: bool,
    pub preparation_command: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GoTarget {
    pub package: String,
    pub test_name: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoExperimentKind {
    MalformedInputPanic,
    FilesystemBoundary,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoFailureKind {
    Panic,
    Race,
    PropertyFailure,
    TestFailure,
    None,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GoFailure {
    pub kind: GoFailureKind,
    pub signature: String,
    pub summary: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FuzzArtifactBundle {
    pub corpus: Vec<StoredArtifact>,
    pub minimized_failure: Option<StoredArtifact>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Reproducer {
    pub image: String,
    pub command: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub oracle: Oracle,
    pub negative_control: Oracle,
}

impl Reproducer {
    /// Replays a deterministic Go experiment without an LLM.
    ///
    /// # Errors
    /// Returns a sandbox execution error.
    pub async fn replay(
        &self,
        runner: &ExperimentRunner,
        root: PathBuf,
        cancellation: CancellationToken,
    ) -> Result<ExperimentEvidence, edsa_adapter_sdk::AdapterError> {
        runner
            .execute(
                ExperimentRequest {
                    sandbox: SandboxRequest {
                        source_root: root,
                        image: self.image.clone(),
                        command: self.command.clone(),
                        environment: self.environment.clone(),
                    },
                    oracle: self.oracle.clone(),
                    negative_control: self.negative_control.clone(),
                },
                cancellation,
            )
            .await
    }
}

#[must_use]
pub fn is_go_repository(inventory: &RepositoryInventory) -> bool {
    inventory.detection.languages.contains(&Language::Go)
}

/// Builds an immutable Go module preparation plan.
///
/// # Errors
/// Returns an error when `go.mod` is absent.
pub fn environment_plan(
    inventory: &RepositoryInventory,
) -> Result<GoEnvironmentPlan, GoAdapterError> {
    let has_module = inventory
        .files
        .iter()
        .any(|file| file.relative_path == "go.mod");
    if !has_module {
        return Err(GoAdapterError::MissingModule);
    }
    let has_sum = inventory
        .files
        .iter()
        .any(|file| file.relative_path == "go.sum");
    Ok(GoEnvironmentPlan {
        image: "golang:1.24-bookworm".into(),
        module_file: "go.mod".into(),
        sum_file: has_sum.then(|| "go.sum".into()),
        locked: has_sum,
        preparation_command: vec!["go".into(), "mod".into(), "download".into()],
    })
}

#[must_use]
pub fn sandbox_policy() -> SandboxPolicy {
    let mut policy = SandboxPolicy::default();
    for name in ["EDSA_NEGATIVE_CONTROL", "GOCACHE", "GOMODCACHE", "GOFLAGS"] {
        policy.allowed_environment.insert(name.into());
    }
    policy
}

fn go_environment() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("GOCACHE".into(), "/tmp/go-build".into()),
        ("GOMODCACHE".into(), "/tmp/go-mod".into()),
        ("GOFLAGS".into(), "-mod=readonly".into()),
    ])
}

#[must_use]
pub fn baseline_request(root: PathBuf, plan: &GoEnvironmentPlan) -> SandboxRequest {
    SandboxRequest {
        source_root: root,
        image: plan.image.clone(),
        command: vec![
            "go".into(),
            "test".into(),
            "./...".into(),
            "-count=1".into(),
        ],
        environment: go_environment(),
    }
}

#[must_use]
pub fn regression_request(root: PathBuf, plan: &GoEnvironmentPlan) -> SandboxRequest {
    baseline_request(root, plan)
}

#[must_use]
pub fn fuzz_request(
    root: PathBuf,
    plan: &GoEnvironmentPlan,
    target: &GoTarget,
    seconds: u32,
) -> SandboxRequest {
    SandboxRequest {
        source_root: root,
        image: plan.image.clone(),
        command: vec![
            "go".into(),
            "test".into(),
            target.package.clone(),
            "-run=^$".into(),
            format!("-fuzz=^{}$", target.test_name),
            format!("-fuzztime={seconds}s"),
            "-parallel=1".into(),
        ],
        environment: go_environment(),
    }
}

#[must_use]
pub fn race_request(root: PathBuf, plan: &GoEnvironmentPlan) -> SandboxRequest {
    SandboxRequest {
        source_root: root,
        image: plan.image.clone(),
        command: vec![
            "go".into(),
            "test".into(),
            "-race".into(),
            "./...".into(),
            "-count=1".into(),
        ],
        environment: go_environment(),
    }
}

#[must_use]
pub fn generated_experiment(
    root: PathBuf,
    plan: &GoEnvironmentPlan,
    kind: GoExperimentKind,
    target: &GoTarget,
) -> (ExperimentRequest, Reproducer) {
    let selector = match kind {
        GoExperimentKind::MalformedInputPanic | GoExperimentKind::FilesystemBoundary => {
            format!("^{}$", target.test_name)
        }
    };
    let command = vec![
        "go".into(),
        "test".into(),
        target.package.clone(),
        format!("-run={selector}"),
        "-count=1".into(),
        "-v".into(),
    ];
    let oracle = oracles::vulnerability_marker();
    let negative_control = oracles::clean_control_marker();
    let environment = go_environment();
    let reproducer = Reproducer {
        image: plan.image.clone(),
        command: command.clone(),
        environment: environment.clone(),
        oracle: oracle.clone(),
        negative_control: negative_control.clone(),
    };
    (
        ExperimentRequest {
            sandbox: SandboxRequest {
                source_root: root,
                image: plan.image.clone(),
                command,
                environment,
            },
            oracle,
            negative_control,
        },
        reproducer,
    )
}

#[must_use]
pub fn classify_failure(execution: &RecordedExecution) -> GoFailure {
    let report = format!("{}\n{}", execution.stdout, execution.stderr);
    let kind = if report.contains("WARNING: DATA RACE") {
        GoFailureKind::Race
    } else if report.contains("panic:") || report.contains("panicked at") {
        GoFailureKind::Panic
    } else if report.contains("Falsified after") || report.contains("failing input") {
        GoFailureKind::PropertyFailure
    } else if execution.exit_code != Some(0) {
        GoFailureKind::TestFailure
    } else {
        GoFailureKind::None
    };
    let summary = stable_report(&report);
    let signature =
        format!("go-{:?}-{:x}", kind, Sha256::digest(summary.as_bytes())).to_ascii_lowercase();
    GoFailure {
        kind,
        signature,
        summary,
    }
}

fn stable_report(report: &str) -> String {
    report
        .lines()
        .map(|line| {
            line.split_whitespace()
                .map(|token| {
                    if token.starts_with("0x")
                        || token.chars().all(|character| character.is_ascii_digit())
                    {
                        "<variable>"
                    } else {
                        token
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|line| !line.is_empty())
        .take(32)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Stores fuzz seeds and an optional minimized failure by content hash.
///
/// # Errors
/// Returns an artifact-store error when storage or integrity validation fails.
pub fn store_fuzz_artifacts(
    store: &ArtifactStore,
    corpus: &[Vec<u8>],
    minimized: Option<&[u8]>,
) -> Result<FuzzArtifactBundle, ArtifactError> {
    let corpus = corpus
        .iter()
        .map(|input| store.put(input))
        .collect::<Result<Vec<_>, _>>()?;
    let minimized_failure = minimized.map(|input| store.put(input)).transpose()?;
    Ok(FuzzArtifactBundle {
        corpus,
        minimized_failure,
    })
}

#[derive(Debug, Error)]
pub enum GoAdapterError {
    #[error("go.mod was not found at the authorized repository root")]
    MissingModule,
}

#[must_use]
pub fn module_root_is_safe(root: &Path) -> bool {
    root.is_dir()
}
