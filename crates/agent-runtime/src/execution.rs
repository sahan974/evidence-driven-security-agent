//! Typed conversion of model hypotheses into allowlisted adapter operations.

use std::{collections::BTreeMap, fs, path::Path, sync::Arc};

use edsa_adapter_sdk::{ExperimentEvidence, ExperimentRunner, RecordedExecution};
use edsa_core::{
    ConfirmationPolicy, EvidenceAssessment, Hypothesis, RepositoryInventory, Signal, Verdict,
};
use edsa_evidence::RunStore;
use edsa_reporting::{
    BuilderDescriptor, BundleArtifactInput, FindingConfidence, ReplayPlan, ReportFinding,
    SourceDescriptor, verify_bundle, write_bundle,
};
use edsa_sandbox::{DockerRunner, SandboxRequest};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectedAdapter {
    Python,
    #[serde(rename = "typescript")]
    TypeScript,
    Go,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeterministicExperiment {
    pub adapter: SelectedAdapter,
    pub baseline: RecordedExecution,
    pub evidence: ExperimentEvidence,
    pub assessment: EvidenceAssessment,
    pub verdict: Verdict,
    pub artifact_sha256: String,
}

#[derive(Deserialize)]
struct StoredExecution {
    baseline: RecordedExecution,
    experiment: ExperimentEvidence,
}

/// Executes only operations expressible by a built-in typed adapter. The
/// designer's free-form command is deliberately not an input to this API.
///
/// # Errors
/// Returns a typed rejection when no safe adapter operation can represent the
/// hypothesis, or an execution, storage, or bundle error after admission.
pub async fn execute_hypothesis(
    root: &Path,
    inventory: &RepositoryInventory,
    hypothesis: &Hypothesis,
    signals: &[Signal],
    store: &RunStore,
    cancellation: &CancellationToken,
) -> Result<DeterministicExperiment, ExperimentDispatchError> {
    if let Some(completed) = restore_completed_experiment(store, hypothesis)? {
        return Ok(completed);
    }
    let signal =
        preferred_signal(hypothesis, signals).ok_or(ExperimentDispatchError::MissingSignal)?;
    match Path::new(&signal.relative_path)
        .extension()
        .and_then(|v| v.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "py" => execute_python(root, inventory, hypothesis, signal, store, cancellation).await,
        "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx" => {
            execute_node(root, inventory, hypothesis, signal, store, cancellation).await
        }
        "go" => execute_go(root, inventory, hypothesis, signal, store, cancellation).await,
        _ => Err(ExperimentDispatchError::UnsupportedProposal(
            "supporting signal has no safe language adapter".into(),
        )),
    }
}

fn restore_completed_experiment(
    store: &RunStore,
    hypothesis: &Hypothesis,
) -> Result<Option<DeterministicExperiment>, ExperimentDispatchError> {
    let case = store.root().join("cases").join(hypothesis.id.as_str());
    if !case.join("manifest.json").is_file() {
        return Ok(None);
    }
    let manifest = verify_bundle(&case)?;
    let finding = manifest
        .findings
        .iter()
        .find(|finding| finding.id == hypothesis.id.as_str())
        .ok_or_else(|| {
            ExperimentDispatchError::UnsupportedProposal(
                "completed case does not contain its hypothesis finding".into(),
            )
        })?;
    let artifact = manifest.artifacts.first().ok_or_else(|| {
        ExperimentDispatchError::UnsupportedProposal(
            "completed case does not contain execution evidence".into(),
        )
    })?;
    let stored: StoredExecution =
        serde_json::from_slice(&fs::read(case.join(&artifact.relative_path))?)?;
    let baseline_passed = stored.baseline.exit_code == Some(0);
    let mut assessment = stored.experiment.assessment(baseline_passed);
    if let Some(reference) = assessment.evidence.first_mut() {
        reference.sha256.clone_from(&artifact.sha256);
        reference.size_bytes = artifact.size_bytes;
    }
    let adapter = match Path::new(&finding.relative_path)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "py" | "pyi" => SelectedAdapter::Python,
        "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" => SelectedAdapter::TypeScript,
        "go" => SelectedAdapter::Go,
        _ => {
            return Err(ExperimentDispatchError::UnsupportedProposal(
                "completed case has no supported adapter".into(),
            ));
        }
    };
    Ok(Some(DeterministicExperiment {
        adapter,
        baseline: stored.baseline,
        evidence: stored.experiment,
        assessment,
        verdict: finding.verdict,
        artifact_sha256: artifact.sha256.clone(),
    }))
}

fn preferred_signal<'a>(hypothesis: &Hypothesis, signals: &'a [Signal]) -> Option<&'a Signal> {
    let mut candidates = signals
        .iter()
        .filter(|signal| hypothesis.signal_ids.contains(&signal.id))
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        signal_source_rank(left)
            .cmp(&signal_source_rank(right))
            .then_with(|| right.start_line.cmp(&left.start_line))
            .then_with(|| left.relative_path.cmp(&right.relative_path))
    });
    candidates.into_iter().next()
}

fn signal_source_rank(signal: &Signal) -> u8 {
    match signal.source {
        edsa_core::SignalSource::ModelProposal => 0,
        edsa_core::SignalSource::Human => 1,
        edsa_core::SignalSource::ExternalAnalyzer => 2,
        edsa_core::SignalSource::BuiltInRule => 3,
    }
}

async fn execute_python(
    root: &Path,
    inventory: &RepositoryInventory,
    hypothesis: &Hypothesis,
    signal: &Signal,
    store: &RunStore,
    cancellation: &CancellationToken,
) -> Result<DeterministicExperiment, ExperimentDispatchError> {
    use edsa_adapter_python::{PythonHypothesisKind, PythonTarget};
    let plan = edsa_adapter_python::environment_plan(inventory);
    let text = hypothesis_text(hypothesis);
    let kind = if has(&text, &["path", "travers"]) {
        PythonHypothesisKind::PathTraversal
    } else if has(&text, &["command", "inject"]) {
        PythonHypothesisKind::CommandInjection
    } else {
        return Err(ExperimentDispatchError::UnsupportedProposal(
            "Python adapter supports path traversal and command injection".into(),
        ));
    };
    let source = fs::read_to_string(root.join(&signal.relative_path))?;
    let target = PythonTarget {
        module: signal
            .relative_path
            .trim_end_matches(".py")
            .replace(['/', '\\'], "."),
        callable: nearest_function(&source, signal.start_line, "def ")?,
        framework: edsa_adapter_python::detect_framework(root, inventory)?,
    };
    let runner = ExperimentRunner::new(Arc::new(DockerRunner::new(
        edsa_adapter_python::sandbox_policy(),
    )));
    let (baseline, passed) = runner
        .baseline(
            edsa_adapter_python::baseline_request(root.to_path_buf(), plan.image.clone()),
            &exit_zero(),
            cancellation.clone(),
        )
        .await?;
    let (request, _) =
        edsa_adapter_python::generated_experiment(root.to_path_buf(), plan.image, kind, &target);
    let policy = edsa_adapter_python::sandbox_policy();
    let replay = replay_plan(hypothesis, &request, &policy);
    finish(
        SelectedAdapter::Python,
        runner.execute(request, cancellation.clone()).await?,
        baseline,
        passed,
        hypothesis,
        signal,
        inventory,
        replay,
        store,
    )
}

async fn execute_node(
    root: &Path,
    inventory: &RepositoryInventory,
    hypothesis: &Hypothesis,
    signal: &Signal,
    store: &RunStore,
    cancellation: &CancellationToken,
) -> Result<DeterministicExperiment, ExperimentDispatchError> {
    use edsa_adapter_typescript::{NodeHypothesisKind, NodeTarget};
    let plan = edsa_adapter_typescript::environment_plan(root, inventory)?;
    let text = hypothesis_text(hypothesis);
    let kind = if has(&text, &["path", "travers"]) {
        NodeHypothesisKind::PathTraversal
    } else if has(&text, &["ssrf", "server-side request"]) {
        NodeHypothesisKind::Ssrf
    } else {
        return Err(ExperimentDispatchError::UnsupportedProposal(
            "Node adapter supports path traversal and SSRF".into(),
        ));
    };
    if matches!(
        Path::new(&signal.relative_path)
            .extension()
            .and_then(|v| v.to_str()),
        Some("ts" | "tsx")
    ) {
        return Err(ExperimentDispatchError::UnsupportedProposal(
            "TypeScript needs a committed runtime loader before safe direct execution".into(),
        ));
    }
    let source = fs::read_to_string(root.join(&signal.relative_path))?;
    let target = NodeTarget {
        module: format!("./{}", signal.relative_path.replace('\\', "/")),
        callable: nearest_js_function(&source, signal.start_line)?,
    };
    let runner = ExperimentRunner::new(Arc::new(DockerRunner::new(
        edsa_adapter_typescript::sandbox_policy(),
    )));
    let (baseline, passed) = runner
        .baseline(
            SandboxRequest {
                source_root: root.to_path_buf(),
                image: plan.image.clone(),
                command: vec![
                    "node".into(),
                    "--check".into(),
                    signal.relative_path.clone(),
                ],
                environment: BTreeMap::new(),
            },
            &exit_zero(),
            cancellation.clone(),
        )
        .await?;
    let (request, _) = edsa_adapter_typescript::generated_experiment(
        root.to_path_buf(),
        plan.image,
        kind,
        &target,
    );
    let policy = edsa_adapter_typescript::sandbox_policy();
    let replay = replay_plan(hypothesis, &request, &policy);
    finish(
        SelectedAdapter::TypeScript,
        runner.execute(request, cancellation.clone()).await?,
        baseline,
        passed,
        hypothesis,
        signal,
        inventory,
        replay,
        store,
    )
}

async fn execute_go(
    root: &Path,
    inventory: &RepositoryInventory,
    hypothesis: &Hypothesis,
    signal: &Signal,
    store: &RunStore,
    cancellation: &CancellationToken,
) -> Result<DeterministicExperiment, ExperimentDispatchError> {
    use edsa_adapter_go::{GoExperimentKind, GoTarget};
    let plan = edsa_adapter_go::environment_plan(inventory)?;
    let text = hypothesis_text(hypothesis);
    let kind = if has(&text, &["path", "filesystem"]) {
        GoExperimentKind::FilesystemBoundary
    } else if has(&text, &["panic", "malformed"]) {
        GoExperimentKind::MalformedInputPanic
    } else {
        return Err(ExperimentDispatchError::UnsupportedProposal(
            "Go adapter supports filesystem boundary and malformed input".into(),
        ));
    };
    let target = GoTarget {
        package: "./...".into(),
        test_name: find_go_test(root, inventory, kind)?,
    };
    let runner = ExperimentRunner::new(Arc::new(DockerRunner::new(
        edsa_adapter_go::sandbox_policy(),
    )));
    let (baseline, passed) = runner
        .baseline(
            edsa_adapter_go::baseline_request(root.to_path_buf(), &plan),
            &exit_zero(),
            cancellation.clone(),
        )
        .await?;
    let (request, _) =
        edsa_adapter_go::generated_experiment(root.to_path_buf(), &plan, kind, &target);
    let policy = edsa_adapter_go::sandbox_policy();
    let replay = replay_plan(hypothesis, &request, &policy);
    finish(
        SelectedAdapter::Go,
        runner.execute(request, cancellation.clone()).await?,
        baseline,
        passed,
        hypothesis,
        signal,
        inventory,
        replay,
        store,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish(
    adapter: SelectedAdapter,
    evidence: ExperimentEvidence,
    baseline: RecordedExecution,
    baseline_passed: bool,
    hypothesis: &Hypothesis,
    signal: &Signal,
    inventory: &RepositoryInventory,
    replay: ReplayPlan,
    store: &RunStore,
) -> Result<DeterministicExperiment, ExperimentDispatchError> {
    let evidence_json = serde_json::from_slice::<serde_json::Value>(&evidence.artifact_bytes()?)?;
    let bytes = serde_json::to_vec(
        &serde_json::json!({ "baseline": baseline, "experiment": evidence_json }),
    )?;
    let artifact = store.store_artifact(&bytes)?;
    let mut assessment = evidence.assessment(baseline_passed);
    if let Some(reference) = assessment.evidence.first_mut() {
        reference.sha256.clone_from(&artifact.sha256);
        reference.size_bytes = artifact.size_bytes;
    }
    let verdict = ConfirmationPolicy::default().verdict(&assessment);
    let case = store.root().join("cases").join(hypothesis.id.as_str());
    write_bundle(
        &case,
        SourceDescriptor {
            repository: inventory.snapshot.repository_path.clone(),
            revision: inventory.snapshot.revision.clone(),
            content_digest: inventory.snapshot.content_digest.clone(),
        },
        BuilderDescriptor {
            id: "edsa-live-scan".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        },
        vec![ReportFinding {
            id: hypothesis.id.as_str().to_owned(),
            rule_id: signal.rule.clone(),
            title: hypothesis.title.clone(),
            message: hypothesis.claim.clone(),
            relative_path: signal.relative_path.clone(),
            start_line: signal.start_line,
            verdict,
            confidence: if verdict == Verdict::Confirmed {
                FindingConfidence::High
            } else {
                FindingConfidence::Medium
            },
            evidence_digests: vec![artifact.sha256.clone()],
        }],
        vec![replay],
        &[],
        vec![BundleArtifactInput {
            logical_name: "baseline-attack-control.json".into(),
            media_type: "application/vnd.edsa.execution+json".into(),
            bytes,
        }],
    )?;
    Ok(DeterministicExperiment {
        adapter,
        baseline,
        evidence,
        assessment,
        verdict,
        artifact_sha256: artifact.sha256,
    })
}

fn replay_plan(
    hypothesis: &Hypothesis,
    request: &edsa_adapter_sdk::ExperimentRequest,
    policy: &edsa_sandbox::SandboxPolicy,
) -> ReplayPlan {
    ReplayPlan {
        finding_id: hypothesis.id.as_str().to_owned(),
        relative_source_root: ".".into(),
        image: request.sandbox.image.clone(),
        command: request.sandbox.command.clone(),
        environment: request.sandbox.environment.clone(),
        sandbox_policy: edsa_reporting::ReplaySandboxPolicy::from(policy),
        oracle: request.oracle.clone(),
        negative_control: request.negative_control.clone(),
    }
}

fn exit_zero() -> edsa_adapter_sdk::Oracle {
    edsa_adapter_sdk::Oracle {
        kind: edsa_core::OracleKind::ExitCode,
        expected: "0".into(),
    }
}
fn hypothesis_text(value: &Hypothesis) -> String {
    format!("{} {} {}", value.title, value.claim, value.weakness).to_ascii_lowercase()
}
fn has(text: &str, words: &[&str]) -> bool {
    words.iter().any(|word| text.contains(word))
}
fn nearest_function(
    source: &str,
    line: u32,
    prefix: &str,
) -> Result<String, ExperimentDispatchError> {
    source
        .lines()
        .take(usize::try_from(line).unwrap_or(usize::MAX))
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .find_map(|line| {
            line.trim_start()
                .strip_prefix(prefix)
                .and_then(|rest| rest.split('(').next())
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
        })
        .ok_or_else(|| {
            ExperimentDispatchError::UnsupportedProposal(
                "no callable could be derived from the source location".into(),
            )
        })
}
fn nearest_js_function(source: &str, line: u32) -> Result<String, ExperimentDispatchError> {
    for item in source
        .lines()
        .take(usize::try_from(line).unwrap_or(usize::MAX))
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        let item = item
            .trim()
            .trim_start_matches("export ")
            .trim_start_matches("async ");
        if let Some(rest) = item.strip_prefix("function ") {
            if let Some(name) = rest.split('(').next() {
                return Ok(name.trim().to_owned());
            }
        }
    }
    Err(ExperimentDispatchError::UnsupportedProposal(
        "no exported JavaScript function could be derived".into(),
    ))
}
fn find_go_test(
    root: &Path,
    inventory: &RepositoryInventory,
    kind: edsa_adapter_go::GoExperimentKind,
) -> Result<String, ExperimentDispatchError> {
    let hint = match kind {
        edsa_adapter_go::GoExperimentKind::FilesystemBoundary => "Boundary",
        edsa_adapter_go::GoExperimentKind::MalformedInputPanic => "Malformed",
    };
    for file in inventory
        .files
        .iter()
        .filter(|file| file.relative_path.ends_with("_test.go"))
    {
        for line in fs::read_to_string(root.join(&file.relative_path))?.lines() {
            if let Some(rest) = line.trim_start().strip_prefix("func Test") {
                if let Some(name) = rest.split('(').next() {
                    let name = format!("Test{}", name.trim());
                    if name.contains(hint) {
                        return Ok(name);
                    }
                }
            }
        }
    }
    Err(ExperimentDispatchError::UnsupportedProposal(
        "no allowlisted Go test expresses this experiment".into(),
    ))
}

#[derive(Debug, Error)]
pub enum ExperimentDispatchError {
    #[error("hypothesis has no admitted supporting signal")]
    MissingSignal,
    #[error("experiment proposal rejected: {0}")]
    UnsupportedProposal(String),
    #[error("repository read failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("adapter execution failed: {0}")]
    Adapter(#[from] edsa_adapter_sdk::AdapterError),
    #[error("Python adapter failed: {0}")]
    Python(#[from] edsa_adapter_python::PythonAdapterError),
    #[error("Node adapter failed: {0}")]
    Node(#[from] edsa_adapter_typescript::TypeScriptAdapterError),
    #[error("Go adapter failed: {0}")]
    Go(#[from] edsa_adapter_go::GoAdapterError),
    #[error("evidence storage failed: {0}")]
    Store(#[from] edsa_evidence::RunStoreError),
    #[error("evidence bundle failed: {0}")]
    Bundle(#[from] edsa_reporting::BundleError),
    #[error("execution serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}
