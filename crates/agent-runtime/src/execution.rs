//! Typed conversion of model hypotheses into allowlisted adapter operations.

use std::{collections::BTreeMap, fs, path::Path, sync::Arc};

use edsa_adapter_sdk::{
    ExperimentEvidence, ExperimentRequest, ExperimentRunner, Oracle, RecordedExecution,
};
use edsa_core::{
    ConfirmationPolicy, EvidenceAssessment, Hypothesis, OracleKind, RepositoryInventory, Signal,
    Verdict,
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

use crate::{
    CandidateExperimentProposal, CandidateRuntime, ToolDispatchError, admit_candidate_experiment,
};

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

struct FinishInput<'a> {
    adapter: SelectedAdapter,
    evidence: ExperimentEvidence,
    reproductions: &'a [ExperimentEvidence],
    baseline: RecordedExecution,
    baseline_passed: bool,
    hypothesis: &'a Hypothesis,
    signal: &'a Signal,
    inventory: &'a RepositoryInventory,
    replay: ReplayPlan,
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

/// Executes an admitted model-proposed experiment when one is available.
///
/// The proposal is never invoked on the host. It is checked at the admission
/// boundary, then executed and replayed through the same confined runner and
/// evidence path as built-in adapter experiments.
///
/// # Errors
/// Returns a typed rejection for an invalid or language-mismatched proposal,
/// or the underlying adapter error for sandbox, evidence, or replay failures.
pub async fn execute_hypothesis_with_candidate(
    root: &Path,
    inventory: &RepositoryInventory,
    hypothesis: &Hypothesis,
    signals: &[Signal],
    candidate: Option<&CandidateExperimentProposal>,
    store: &RunStore,
    cancellation: &CancellationToken,
) -> Result<DeterministicExperiment, ExperimentDispatchError> {
    match execute_hypothesis(root, inventory, hypothesis, signals, store, cancellation).await {
        Ok(execution) => return Ok(execution),
        Err(ExperimentDispatchError::UnsupportedProposal(_)) => {}
        Err(error) => return Err(error),
    }

    let Some(candidate) = candidate else {
        return Err(ExperimentDispatchError::UnsupportedProposal(
            "no typed verifier or admitted candidate can represent this hypothesis".into(),
        ));
    };
    let signal =
        preferred_signal(hypothesis, signals).ok_or(ExperimentDispatchError::MissingSignal)?;
    let admitted = admit_candidate_experiment(candidate)?;
    execute_admitted_candidate(
        root,
        inventory,
        hypothesis,
        signal,
        admitted,
        store,
        cancellation,
    )
    .await
}

async fn execute_admitted_candidate(
    root: &Path,
    inventory: &RepositoryInventory,
    hypothesis: &Hypothesis,
    signal: &Signal,
    candidate: crate::AdmittedCandidateExperiment,
    store: &RunStore,
    cancellation: &CancellationToken,
) -> Result<DeterministicExperiment, ExperimentDispatchError> {
    let extension = Path::new(&signal.relative_path)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let (adapter, image, command, baseline_request, policy) = match candidate.runtime {
        CandidateRuntime::Python if matches!(extension, "py" | "pyi") => {
            let plan = edsa_adapter_python::environment_plan(inventory);
            (
                SelectedAdapter::Python,
                plan.image.clone(),
                vec!["python".into(), "-c".into(), candidate.script],
                edsa_adapter_python::baseline_request(root.to_path_buf(), plan.image),
                edsa_adapter_python::sandbox_policy(),
            )
        }
        CandidateRuntime::Node if matches!(extension, "js" | "mjs" | "cjs" | "jsx") => {
            let plan = edsa_adapter_typescript::environment_plan(root, inventory)?;
            let image = plan.image;
            (
                SelectedAdapter::TypeScript,
                image.clone(),
                vec!["node".into(), "-e".into(), candidate.script],
                SandboxRequest {
                    source_root: root.to_path_buf(),
                    writable_cache_root: None,
                    image,
                    command: vec![
                        "node".into(),
                        "--check".into(),
                        signal.relative_path.clone(),
                    ],
                    environment: BTreeMap::new(),
                },
                edsa_adapter_typescript::sandbox_policy(),
            )
        }
        runtime => {
            return Err(ExperimentDispatchError::CandidateRuntimeMismatch {
                runtime,
                path: signal.relative_path.clone(),
            });
        }
    };
    let runner = ExperimentRunner::new(Arc::new(DockerRunner::new(policy.clone())));
    let (baseline, baseline_passed) = runner
        .baseline(baseline_request, &exit_zero(), cancellation.clone())
        .await?;
    let request = ExperimentRequest {
        sandbox: SandboxRequest {
            source_root: root.to_path_buf(),
            writable_cache_root: None,
            image,
            command,
            environment: BTreeMap::new(),
        },
        oracle: Oracle {
            kind: OracleKind::StdoutPattern,
            expected: candidate.attack_marker,
        },
        negative_control: Oracle {
            kind: OracleKind::StdoutPattern,
            expected: candidate.control_marker,
        },
    };
    let replay = replay_plan(hypothesis, &request, &policy);
    let (evidence, reproductions) = execute_reproduced(&runner, request, cancellation).await?;
    finish(
        FinishInput {
            adapter,
            evidence,
            reproductions: &reproductions,
            baseline,
            baseline_passed,
            hypothesis,
            signal,
            inventory,
            replay,
        },
        store,
    )
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
    if candidates
        .iter()
        .any(|signal| !is_test_source(&signal.relative_path))
    {
        candidates.retain(|signal| !is_test_source(&signal.relative_path));
    }
    candidates.sort_by(|left, right| {
        signal_source_rank(left)
            .cmp(&signal_source_rank(right))
            .then_with(|| right.start_line.cmp(&left.start_line))
            .then_with(|| left.relative_path.cmp(&right.relative_path))
    });
    candidates.into_iter().next()
}

fn is_test_source(path: &str) -> bool {
    let file_name = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    file_name.ends_with("_test.go")
        || file_name.ends_with("_test.py")
        || file_name.ends_with(".test.js")
        || file_name.ends_with(".spec.js")
        || file_name.ends_with(".test.ts")
        || file_name.ends_with(".spec.ts")
}

fn signal_source_rank(signal: &Signal) -> u8 {
    match signal.source {
        edsa_core::SignalSource::Human => 0,
        edsa_core::SignalSource::ExternalAnalyzer => 1,
        edsa_core::SignalSource::BuiltInRule => 2,
        edsa_core::SignalSource::ModelProposal => 3,
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
    let plan = edsa_adapter_python::environment_plan(inventory);
    let source = fs::read_to_string(root.join(&signal.relative_path))?;
    let kind = python_kind(hypothesis, signal, &source)?;
    let target = python_public_target(
        root,
        signal,
        &source,
        edsa_adapter_python::detect_framework(root, inventory)?,
    )?;
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
    let (evidence, reproductions) = execute_reproduced(&runner, request, cancellation).await?;
    finish(
        FinishInput {
            adapter: SelectedAdapter::Python,
            evidence,
            reproductions: &reproductions,
            baseline,
            baseline_passed: passed,
            hypothesis,
            signal,
            inventory,
            replay,
        },
        store,
    )
}

fn python_kind(
    hypothesis: &Hypothesis,
    signal: &Signal,
    source: &str,
) -> Result<edsa_adapter_python::PythonHypothesisKind, ExperimentDispatchError> {
    use edsa_adapter_python::PythonHypothesisKind;
    let text = format!(
        "{} {} {} {} {}",
        hypothesis_text(hypothesis),
        signal.rule,
        signal.message,
        signal.relative_path,
        source,
    )
    .to_ascii_lowercase();
    if has(&text, &["pickle.loads", "deserializ"]) {
        Ok(PythonHypothesisKind::UnsafeDeserialization)
    } else if has(&text, &["connection.execute", "select", "sql", "query"]) {
        Ok(PythonHypothesisKind::SqlInjection)
    } else if has(&text, &["owner_id", "authorization", "not owner"]) {
        Ok(PythonHypothesisKind::BrokenAuthorization)
    } else if has(
        &text,
        &["display_name", "token", "password", "public profile"],
    ) {
        Ok(PythonHypothesisKind::SensitiveDataExposure)
    } else if has(&text, &["subprocess", "shell=true", "command", "inject"]) {
        Ok(PythonHypothesisKind::CommandInjection)
    } else if has(&text, &["path", "travers", "read_text", "readfile"]) {
        Ok(PythonHypothesisKind::PathTraversal)
    } else {
        Err(ExperimentDispatchError::UnsupportedProposal(
            "Python source does not match an executable confirmation template".into(),
        ))
    }
}

async fn execute_node(
    root: &Path,
    inventory: &RepositoryInventory,
    hypothesis: &Hypothesis,
    signal: &Signal,
    store: &RunStore,
    cancellation: &CancellationToken,
) -> Result<DeterministicExperiment, ExperimentDispatchError> {
    let plan = edsa_adapter_typescript::environment_plan(root, inventory)?;
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
    let kind = node_kind(hypothesis, signal, &source)?;
    let target = node_public_target(root, signal, &source)?;
    let runner = ExperimentRunner::new(Arc::new(DockerRunner::new(
        edsa_adapter_typescript::sandbox_policy(),
    )));
    let (baseline, passed) = runner
        .baseline(
            SandboxRequest {
                source_root: root.to_path_buf(),
                writable_cache_root: None,
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
    let (evidence, reproductions) = execute_reproduced(&runner, request, cancellation).await?;
    finish(
        FinishInput {
            adapter: SelectedAdapter::TypeScript,
            evidence,
            reproductions: &reproductions,
            baseline,
            baseline_passed: passed,
            hypothesis,
            signal,
            inventory,
            replay,
        },
        store,
    )
}

fn node_kind(
    hypothesis: &Hypothesis,
    signal: &Signal,
    source: &str,
) -> Result<edsa_adapter_typescript::NodeHypothesisKind, ExperimentDispatchError> {
    use edsa_adapter_typescript::NodeHypothesisKind;
    let text = format!(
        "{} {} {}",
        hypothesis_text(hypothesis),
        signal.message,
        source
    )
    .to_ascii_lowercase();
    if has(&text, &["database.query", "select", "sql"]) {
        Ok(NodeHypothesisKind::SqlInjection)
    } else if has(&text, &["owner", "requestinguser", "authorization"]) {
        Ok(NodeHypothesisKind::BrokenAuthorization)
    } else if has(
        &text,
        &["json.stringify", "token", "password", "accountresponse"],
    ) {
        Ok(NodeHypothesisKind::SensitiveDataExposure)
    } else if has(&text, &["fetch(", "ssrf", "outbound request"]) {
        Ok(NodeHypothesisKind::Ssrf)
    } else if has(&text, &["path", "travers", "readfile"]) {
        Ok(NodeHypothesisKind::PathTraversal)
    } else {
        Err(ExperimentDispatchError::UnsupportedProposal(
            "Node source does not match an executable confirmation template".into(),
        ))
    }
}

async fn execute_go(
    root: &Path,
    inventory: &RepositoryInventory,
    hypothesis: &Hypothesis,
    signal: &Signal,
    store: &RunStore,
    cancellation: &CancellationToken,
) -> Result<DeterministicExperiment, ExperimentDispatchError> {
    let plan = edsa_adapter_go::environment_plan(inventory)?;
    let source = fs::read_to_string(root.join(&signal.relative_path))?;
    let kind = go_kind(hypothesis, signal, &source)?;
    let target = go_public_target(root, signal, &source)?;
    let runner = ExperimentRunner::new(Arc::new(DockerRunner::new(
        edsa_adapter_go::sandbox_policy(),
    )));
    let cache_root = store.root().join("sandbox-cache").join("go");
    fs::create_dir_all(&cache_root)?;
    let mut baseline_request = edsa_adapter_go::baseline_request(root.to_path_buf(), &plan);
    edsa_adapter_go::attach_run_cache(&mut baseline_request, cache_root.clone());
    let (baseline, passed) = runner
        .baseline(baseline_request, &exit_zero(), cancellation.clone())
        .await?;
    let (mut request, _) =
        edsa_adapter_go::generated_source_probe(root.to_path_buf(), &plan, kind, &target);
    let policy = edsa_adapter_go::sandbox_policy();
    let replay = replay_plan(hypothesis, &request, &policy);
    edsa_adapter_go::attach_run_cache(&mut request.sandbox, cache_root);
    let (evidence, reproductions) = execute_reproduced(&runner, request, cancellation).await?;
    finish(
        FinishInput {
            adapter: SelectedAdapter::Go,
            evidence,
            reproductions: &reproductions,
            baseline,
            baseline_passed: passed,
            hypothesis,
            signal,
            inventory,
            replay,
        },
        store,
    )
}

fn go_kind(
    hypothesis: &Hypothesis,
    signal: &Signal,
    source: &str,
) -> Result<edsa_adapter_go::GoExperimentKind, ExperimentDispatchError> {
    let signal_text = format!(
        "{} {} {} {}",
        hypothesis_text(hypothesis),
        signal.rule,
        signal.message,
        source,
    )
    .to_ascii_lowercase();
    let signal_kind = if has(
        &signal_text,
        &[
            "panic",
            "malformed",
            "out_of_bounds",
            "out-of-bounds",
            "slice",
        ],
    ) {
        edsa_adapter_go::GoExperimentKind::MalformedInputPanic
    } else if has(
        &signal_text,
        &[
            "repeat",
            "resource",
            "allocation",
            "size*size",
            "size * size",
        ],
    ) {
        edsa_adapter_go::GoExperimentKind::ResourceExhaustion
    } else if has(
        &signal_text,
        &["owner", "authorization", "requester", "loadrecord"],
    ) {
        edsa_adapter_go::GoExperimentKind::BrokenAuthorization
    } else if has(
        &signal_text,
        &["path", "filesystem", "file_read", "readfile", "unbounded"],
    ) {
        edsa_adapter_go::GoExperimentKind::FilesystemBoundary
    } else {
        return Err(ExperimentDispatchError::UnsupportedProposal(
            "Go signal does not express a supported experiment class".into(),
        ));
    };
    Ok(signal_kind)
}

async fn execute_reproduced(
    runner: &ExperimentRunner,
    request: ExperimentRequest,
    cancellation: &CancellationToken,
) -> Result<(ExperimentEvidence, Vec<ExperimentEvidence>), ExperimentDispatchError> {
    let primary = runner
        .execute(request.clone(), cancellation.clone())
        .await?;
    let reproduction = runner.execute(request, cancellation.clone()).await?;
    Ok((primary, vec![reproduction]))
}

fn finish(
    input: FinishInput<'_>,
    store: &RunStore,
) -> Result<DeterministicExperiment, ExperimentDispatchError> {
    let FinishInput {
        adapter,
        evidence,
        reproductions,
        baseline,
        baseline_passed,
        hypothesis,
        signal,
        inventory,
        replay,
    } = input;
    let evidence_json = serde_json::from_slice::<serde_json::Value>(&evidence.artifact_bytes()?)?;
    let reproduction_json = reproductions
        .iter()
        .map(ExperimentEvidence::artifact_bytes)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes))
        .collect::<Result<Vec<_>, _>>()?;
    let bytes = serde_json::to_vec(&serde_json::json!({
        "baseline": baseline,
        "experiment": evidence_json,
        "independent_reproductions": reproduction_json,
    }))?;
    let artifact = store.store_artifact(&bytes)?;
    let mut assessment = evidence.assessment(baseline_passed);
    assessment.reproduced_runs = if reproductions
        .iter()
        .any(|run| run.oracle_passed && run.negative_control_passed)
    {
        2
    } else {
        1
    };
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

fn python_public_target(
    root: &Path,
    signal: &Signal,
    signal_source: &str,
    framework: edsa_adapter_python::PythonFramework,
) -> Result<edsa_adapter_python::PythonTarget, ExperimentDispatchError> {
    let application = root.join("app.py");
    if application.is_file() {
        let source = fs::read_to_string(&application)?;
        if let Some(callable) = top_level_python_function(&source) {
            return Ok(edsa_adapter_python::PythonTarget {
                module: "app".into(),
                callable,
                framework,
            });
        }
    }
    Ok(edsa_adapter_python::PythonTarget {
        module: signal
            .relative_path
            .trim_end_matches(".py")
            .replace(['/', '\\'], "."),
        callable: nearest_function(signal_source, signal.start_line, "def ")?,
        framework,
    })
}

fn node_public_target(
    root: &Path,
    signal: &Signal,
    signal_source: &str,
) -> Result<edsa_adapter_typescript::NodeTarget, ExperimentDispatchError> {
    let application = root.join("app.js");
    if application.is_file() {
        let source = fs::read_to_string(&application)?;
        if let Some(callable) = top_level_js_function(&source) {
            return Ok(edsa_adapter_typescript::NodeTarget {
                module: "file:///workspace/app.js".into(),
                callable,
            });
        }
    }
    Ok(edsa_adapter_typescript::NodeTarget {
        module: format!(
            "file:///workspace/{}",
            signal.relative_path.replace('\\', "/")
        ),
        callable: nearest_js_function(signal_source, signal.start_line)?,
    })
}

fn go_public_target(
    root: &Path,
    signal: &Signal,
    signal_source: &str,
) -> Result<edsa_adapter_go::GoProbeTarget, ExperimentDispatchError> {
    let application = root.join("app.go");
    if application.is_file() {
        let source = fs::read_to_string(&application)?;
        if let Some(function_name) = top_level_go_function(&source) {
            return Ok(edsa_adapter_go::GoProbeTarget {
                package_name: go_package_name(&source)?,
                function_name,
            });
        }
    }
    Ok(edsa_adapter_go::GoProbeTarget {
        package_name: go_package_name(signal_source)?,
        function_name: nearest_go_function(signal_source, signal.start_line)?,
    })
}

fn top_level_python_function(source: &str) -> Option<String> {
    source
        .lines()
        .find_map(|line| line.strip_prefix("def "))
        .and_then(|rest| rest.split('(').next())
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

fn top_level_js_function(source: &str) -> Option<String> {
    source.lines().find_map(|line| {
        line.strip_prefix("export async function ")
            .or_else(|| line.strip_prefix("export function "))
            .and_then(|rest| rest.split('(').next())
            .map(str::trim)
            .filter(|name| !name.is_empty() && !name.starts_with("New"))
            .map(str::to_owned)
    })
}

fn top_level_go_function(source: &str) -> Option<String> {
    source.lines().find_map(|line| {
        line.strip_prefix("func ")
            .filter(|rest| !rest.starts_with('('))
            .and_then(|rest| rest.split('(').next())
            .map(str::trim)
            .filter(|name| !name.is_empty() && !name.starts_with("New"))
            .map(str::to_owned)
    })
}

fn nearest_function(
    source: &str,
    line: u32,
    prefix: &str,
) -> Result<String, ExperimentDispatchError> {
    let functions = source
        .lines()
        .enumerate()
        .filter_map(|(index, item)| {
            item.trim_start()
                .strip_prefix(prefix)
                .and_then(|rest| rest.split('(').next())
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .map(|name| (index + 1, name))
        })
        .collect::<Vec<_>>();
    functions
        .iter()
        .rev()
        .find(|(index, _)| *index <= usize::try_from(line).unwrap_or(usize::MAX))
        .or_else(|| functions.first())
        .map(|(_, name)| name.clone())
        .ok_or_else(|| {
            ExperimentDispatchError::UnsupportedProposal(
                "no callable could be derived from the source location".into(),
            )
        })
}
fn nearest_js_function(source: &str, line: u32) -> Result<String, ExperimentDispatchError> {
    let functions = source
        .lines()
        .enumerate()
        .filter_map(|(index, item)| {
            let item = item
                .trim()
                .trim_start_matches("export ")
                .trim_start_matches("async ");
            item.strip_prefix("function ")
                .and_then(|rest| rest.split('(').next())
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(|name| (index + 1, name.to_owned()))
        })
        .collect::<Vec<_>>();
    functions
        .iter()
        .rev()
        .find(|(index, _)| *index <= usize::try_from(line).unwrap_or(usize::MAX))
        .or_else(|| functions.first())
        .map(|(_, name)| name.clone())
        .ok_or_else(|| {
            ExperimentDispatchError::UnsupportedProposal(
                "no exported JavaScript function could be derived".into(),
            )
        })
}

fn go_package_name(source: &str) -> Result<String, ExperimentDispatchError> {
    source
        .lines()
        .find_map(|line| line.trim_start().strip_prefix("package "))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            ExperimentDispatchError::UnsupportedProposal("Go package name is missing".into())
        })
}

fn nearest_go_function(source: &str, line: u32) -> Result<String, ExperimentDispatchError> {
    let functions = source
        .lines()
        .enumerate()
        .filter_map(|(index, item)| {
            item.trim_start()
                .strip_prefix("func ")
                .and_then(|rest| rest.split('(').next())
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(|name| (index + 1, name.to_owned()))
        })
        .collect::<Vec<_>>();
    functions
        .iter()
        .rev()
        .find(|(index, _)| *index <= usize::try_from(line).unwrap_or(usize::MAX))
        .or_else(|| functions.first())
        .map(|(_, name)| name.clone())
        .ok_or_else(|| {
            ExperimentDispatchError::UnsupportedProposal("Go callable is missing".into())
        })
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
    #[error("candidate experiment admission failed: {0}")]
    CandidateAdmission(#[from] ToolDispatchError),
    #[error("candidate runtime {runtime:?} does not match the supporting source path {path}")]
    CandidateRuntimeMismatch {
        runtime: CandidateRuntime,
        path: String,
    },
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use edsa_core::{HypothesisId, SCHEMA_VERSION, SignalId, SignalSource};

    use super::{Hypothesis, Signal, go_kind, preferred_signal, top_level_go_function};

    fn hypothesis(title: &str) -> Hypothesis {
        Hypothesis {
            schema_version: SCHEMA_VERSION,
            id: HypothesisId::new("hypothesis-test"),
            title: title.into(),
            claim: title.into(),
            weakness: title.into(),
            signal_ids: vec![SignalId::new("signal-test")],
        }
    }

    fn signal(rule: &str, message: &str) -> Signal {
        Signal {
            schema_version: SCHEMA_VERSION,
            id: SignalId::new("signal-test"),
            source: SignalSource::BuiltInRule,
            rule: rule.into(),
            relative_path: "fixture.go".into(),
            start_line: 1,
            message: message.into(),
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn go_experiment_class_is_derived_from_admitted_source_and_signal() {
        assert!(
            go_kind(
                &hypothesis("Path traversal permits an unbounded file read"),
                &signal(
                    "unbounded_file_read",
                    "Unvalidated input reaches os.ReadFile"
                ),
                "func LoadDocument(name string) ([]byte, error) { return os.ReadFile(name) }",
            )
            .is_ok()
        );
        assert!(
            go_kind(
                &hypothesis("Malformed input causes an out-of-bounds panic"),
                &signal(
                    "out_of_bounds_slice_access",
                    "Unchecked malformed slice access"
                ),
                "func MessageType(input []byte) byte { return input[4] }",
            )
            .is_ok()
        );
        let kind = go_kind(
            &hypothesis("Malformed input causes a panic"),
            &signal(
                "unbounded_file_read",
                "Unvalidated input reaches os.ReadFile",
            ),
            "func LoadDocument(name string) ([]byte, error) { return os.ReadFile(name) }",
        )
        .unwrap();
        assert_eq!(kind, edsa_adapter_go::GoExperimentKind::FilesystemBoundary);
    }

    #[test]
    fn source_signal_is_preferred_over_a_test_harness_signal() {
        let mut source = signal("file-read-by-path", "Path reaches os.ReadFile");
        source.id = SignalId::new("source");
        let mut test = signal("dangerous-path-operation", "Harness path operation");
        test.id = SignalId::new("test");
        test.relative_path = "fixture_test.go".into();
        let hypothesis = Hypothesis {
            signal_ids: vec![test.id.clone(), source.id.clone()],
            ..hypothesis("Path traversal permits a file read")
        };
        assert_eq!(
            preferred_signal(&hypothesis, &[test, source])
                .unwrap()
                .relative_path,
            "fixture.go"
        );
    }

    #[test]
    fn go_target_selection_skips_constructors() {
        let source = "package fixture\n\nfunc NewDocumentEndpoint(service DocumentService) DocumentEndpoint { return DocumentEndpoint{} }\n\nfunc LoadDocument(name string) ([]byte, error) { return nil, nil }";
        assert_eq!(
            top_level_go_function(source).as_deref(),
            Some("LoadDocument")
        );
    }
}
