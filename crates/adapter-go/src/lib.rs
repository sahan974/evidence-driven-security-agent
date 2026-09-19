//! Go repository investigation adapter using native Go test tooling.

pub mod oracles;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

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
    BrokenAuthorization,
    ResourceExhaustion,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GoProbeTarget {
    pub package_name: String,
    pub function_name: String,
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
                        writable_cache_root: None,
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
    // Compiling the Go standard library exceeds the generic 64 MB temporary
    // filesystem. This remains an isolated, non-executable tmpfs and does not
    // make the repository mount writable.
    // A cold Go standard-library build in a fresh container can exceed the
    // generic one-minute runtime, especially under Docker Desktop.
    let mut policy = SandboxPolicy {
        tmpfs_size: "512m".into(),
        temporary_filesystem_executable: true,
        timeout: Duration::from_secs(180),
        ..SandboxPolicy::default()
    };
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

/// Attaches a run-owned compiler cache to a Go sandbox request. The cache is
/// outside the repository mount, so source remains immutable while the
/// baseline, probe, and control can reuse compiled standard-library objects.
pub fn attach_run_cache(request: &mut SandboxRequest, cache_root: PathBuf) {
    request.writable_cache_root = Some(cache_root);
    request
        .environment
        .insert("GOCACHE".into(), "/edsa-cache/go-build".into());
    request
        .environment
        .insert("GOMODCACHE".into(), "/edsa-cache/go-mod".into());
}

#[must_use]
pub fn baseline_request(root: PathBuf, plan: &GoEnvironmentPlan) -> SandboxRequest {
    SandboxRequest {
        source_root: root,
        writable_cache_root: None,
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
        writable_cache_root: None,
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
        writable_cache_root: None,
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
        GoExperimentKind::MalformedInputPanic
        | GoExperimentKind::FilesystemBoundary
        | GoExperimentKind::BrokenAuthorization
        | GoExperimentKind::ResourceExhaustion => {
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
                writable_cache_root: None,
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

/// Builds a temporary Go test harness inside `/tmp`, never in the read-only
/// repository mount. The harness is copied with the admitted source and is
/// discarded with the container.
#[must_use]
pub fn generated_source_probe(
    root: PathBuf,
    plan: &GoEnvironmentPlan,
    kind: GoExperimentKind,
    target: &GoProbeTarget,
) -> (ExperimentRequest, Reproducer) {
    let test_source = match kind {
        GoExperimentKind::FilesystemBoundary => format!(
            "package {package}\nimport (\"fmt\"; \"os\"; \"testing\")\nfunc TestEDSAGeneratedProbe(t *testing.T) {{ control := os.Getenv(\"EDSA_NEGATIVE_CONTROL\") == \"1\"; _ = os.MkdirAll(\"documents\", 0755); _ = os.WriteFile(\"documents/safe.txt\", []byte(\"safe\"), 0644); input := \"../../../etc/passwd\"; if control {{ input = \"documents/safe.txt\" }}; value, err := {function}(input); vulnerable := !control && err == nil && len(value) > 0; clean := control && err == nil; if clean {{ fmt.Println(\"EDSA_CONTROL_CLEAN\") }} else if vulnerable {{ fmt.Println(\"EDSA_VULNERABLE\") }} else {{ fmt.Println(\"EDSA_NOT_REPRODUCED\") }} }}\n",
            package = target.package_name,
            function = target.function_name,
        ),
        GoExperimentKind::MalformedInputPanic => format!(
            "package {package}\nimport (\"fmt\"; \"os\"; \"testing\")\nfunc TestEDSAGeneratedProbe(t *testing.T) {{ control := os.Getenv(\"EDSA_NEGATIVE_CONTROL\") == \"1\"; input := []byte{{}}; if control {{ input = []byte{{0,0,0,0,1}} }}; panicked := false; func() {{ defer func() {{ if recover() != nil {{ panicked = true }} }}(); _ = {function}(input) }}(); if control && !panicked {{ fmt.Println(\"EDSA_CONTROL_CLEAN\") }} else if !control && panicked {{ fmt.Println(\"EDSA_VULNERABLE\") }} else {{ fmt.Println(\"EDSA_NOT_REPRODUCED\") }} }}\n",
            package = target.package_name,
            function = target.function_name,
        ),
        GoExperimentKind::BrokenAuthorization => format!(
            "package {package}\nimport (\"fmt\"; \"os\"; \"testing\")\nfunc TestEDSAGeneratedProbe(t *testing.T) {{ control := os.Getenv(\"EDSA_NEGATIVE_CONTROL\") == \"1\"; records := map[string]Record{{\"record-1\":{{Owner:\"owner\",Value:\"private\"}}}}; requester := \"attacker\"; if control {{ requester = \"owner\" }}; result := {function}(records,\"record-1\",requester); vulnerable := !control && result.Value == \"private\"; clean := control && result.Value == \"private\"; if clean {{ fmt.Println(\"EDSA_CONTROL_CLEAN\") }} else if vulnerable {{ fmt.Println(\"EDSA_VULNERABLE\") }} else {{ fmt.Println(\"EDSA_NOT_REPRODUCED\") }} }}\n",
            package = target.package_name,
            function = target.function_name,
        ),
        GoExperimentKind::ResourceExhaustion => format!(
            "package {package}\nimport (\"fmt\"; \"os\"; \"testing\")\nfunc TestEDSAGeneratedProbe(t *testing.T) {{ control := os.Getenv(\"EDSA_NEGATIVE_CONTROL\") == \"1\"; size := 8; if !control {{ size = 2048 }}; value := {function}(size); vulnerable := !control && len(value) > 1000000; clean := control && len(value) == 64; if clean {{ fmt.Println(\"EDSA_CONTROL_CLEAN\") }} else if vulnerable {{ fmt.Println(\"EDSA_VULNERABLE\") }} else {{ fmt.Println(\"EDSA_NOT_REPRODUCED\") }} }}\n",
            package = target.package_name,
            function = target.function_name,
        ),
    };
    let encoded = test_source.replace('"', "\\\"");
    let script = format!(
        "set -eu; cp -R /workspace/. /tmp/edsa; printf '%s' \"{encoded}\" > /tmp/edsa/edsa_generated_test.go; cd /tmp/edsa; go test ./... -run '^TestEDSAGeneratedProbe$' -count=1 -v",
    );
    let command = vec!["sh".into(), "-c".into(), script];
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
                writable_cache_root: None,
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
