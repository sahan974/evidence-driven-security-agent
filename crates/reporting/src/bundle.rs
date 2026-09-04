use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use edsa_adapter_sdk::{
    ExperimentEvidence, ExperimentRequest, ExperimentRunner, Oracle, SandboxBackend,
};
use edsa_core::{RunEvent, RunStatus, SCHEMA_VERSION};
use edsa_evidence::InvestigationEvent;
use edsa_sandbox::{SandboxPolicy, SandboxRequest, sensitive_environment_name};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::{ReportFinding, export_sarif, validate_sarif};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceDescriptor {
    pub repository: String,
    pub revision: String,
    pub content_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuilderDescriptor {
    pub id: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplayPlan {
    pub finding_id: String,
    pub relative_source_root: String,
    pub image: String,
    pub command: Vec<String>,
    pub environment: BTreeMap<String, String>,
    #[serde(default)]
    pub sandbox_policy: ReplaySandboxPolicy,
    pub oracle: Oracle,
    pub negative_control: Oracle,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplaySandboxPolicy {
    pub run_as_user: String,
    pub cpu_limit: String,
    pub memory_limit: String,
    pub pids_limit: u32,
    pub timeout_seconds: u64,
    pub cleanup_timeout_seconds: u64,
    pub maximum_output_bytes_per_stream: usize,
    pub tmpfs_size: String,
    pub temporary_filesystem_executable: bool,
}

impl Default for ReplaySandboxPolicy {
    fn default() -> Self {
        Self::from(&SandboxPolicy::default())
    }
}

impl From<&SandboxPolicy> for ReplaySandboxPolicy {
    fn from(policy: &SandboxPolicy) -> Self {
        Self {
            run_as_user: policy.run_as_user.clone(),
            cpu_limit: policy.cpu_limit.clone(),
            memory_limit: policy.memory_limit.clone(),
            pids_limit: policy.pids_limit,
            timeout_seconds: policy.timeout.as_secs(),
            cleanup_timeout_seconds: policy.cleanup_timeout.as_secs(),
            maximum_output_bytes_per_stream: policy.maximum_output_bytes_per_stream,
            tmpfs_size: policy.tmpfs_size.clone(),
            temporary_filesystem_executable: policy.temporary_filesystem_executable,
        }
    }
}

impl ReplaySandboxPolicy {
    pub fn apply_to(&self, policy: &mut SandboxPolicy) {
        policy.run_as_user.clone_from(&self.run_as_user);
        policy.cpu_limit.clone_from(&self.cpu_limit);
        policy.memory_limit.clone_from(&self.memory_limit);
        policy.pids_limit = self.pids_limit;
        policy.timeout = Duration::from_secs(self.timeout_seconds);
        policy.cleanup_timeout = Duration::from_secs(self.cleanup_timeout_seconds);
        policy.maximum_output_bytes_per_stream = self.maximum_output_bytes_per_stream;
        policy.tmpfs_size.clone_from(&self.tmpfs_size);
        policy.temporary_filesystem_executable = self.temporary_filesystem_executable;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleArtifactInput {
    pub logical_name: String,
    pub media_type: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BundleArtifact {
    pub logical_name: String,
    pub media_type: String,
    pub relative_path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BundleFile {
    pub relative_path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceBundleManifest {
    pub schema_version: u16,
    pub source: SourceDescriptor,
    pub builder: BuilderDescriptor,
    pub findings: Vec<ReportFinding>,
    pub replay_plans: Vec<ReplayPlan>,
    pub artifacts: Vec<BundleArtifact>,
    pub generated_files: Vec<BundleFile>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunReport {
    pub schema_version: u16,
    pub run_id: String,
    pub status: RunStatus,
    pub signals: Vec<serde_json::Value>,
    pub hypotheses: Vec<serde_json::Value>,
    pub experiments: Vec<serde_json::Value>,
    pub verdicts: BTreeMap<String, usize>,
    pub limitations: Vec<String>,
    pub failures: Vec<String>,
    pub resource_usage: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestationSubject {
    pub name: String,
    pub digest: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestationPredicate {
    pub source: SourceDescriptor,
    pub builder: BuilderDescriptor,
    pub commands: Vec<Vec<String>>,
    pub artifact_digests: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceAttestation {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<AttestationSubject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: AttestationPredicate,
}

/// Writes an offline-verifiable evidence bundle into a new or empty directory.
///
/// # Errors
/// Returns an error for unsafe paths, duplicate finding IDs, invalid SARIF, serialization,
/// or filesystem failures.
pub fn write_bundle(
    root: &Path,
    source: SourceDescriptor,
    builder: BuilderDescriptor,
    mut findings: Vec<ReportFinding>,
    mut replay_plans: Vec<ReplayPlan>,
    events: &[InvestigationEvent],
    artifacts: Vec<BundleArtifactInput>,
) -> Result<EvidenceBundleManifest, BundleError> {
    if replay_plans
        .iter()
        .flat_map(|plan| plan.environment.keys())
        .any(|name| sensitive_environment_name(name))
    {
        return Err(BundleError::SensitiveReplayEnvironment);
    }
    ensure_empty(root)?;
    fs::create_dir_all(root.join("artifacts"))?;
    fs::create_dir_all(root.join("reports"))?;
    findings.sort_by(|left, right| left.id.cmp(&right.id));
    replay_plans.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    unique_ids(&findings, &replay_plans)?;

    let stored_artifacts = write_artifacts(root, artifacts)?;
    validate_evidence_references(&findings, &stored_artifacts)?;
    let sarif = export_sarif(&findings);
    validate_sarif(&sarif)?;
    let sarif_bytes = serde_json::to_vec_pretty(&sarif)?;
    let markdown = markdown_summary(&source, &findings).into_bytes();
    let jsonl = events_jsonl(events)?;
    let findings_json = serde_json::to_vec_pretty(&findings)?;
    let replay_json = serde_json::to_vec_pretty(&replay_plans)?;
    let mut generated_files = Vec::new();
    for (path, bytes) in [
        ("reports/results.sarif", sarif_bytes.as_slice()),
        ("reports/results.json", findings_json.as_slice()),
        ("reports/replay.json", replay_json.as_slice()),
        ("reports/summary.md", markdown.as_slice()),
        ("events.jsonl", jsonl.as_slice()),
    ] {
        fs::write(root.join(path), bytes)?;
        generated_files.push(file_record(path, bytes));
    }
    let manifest = EvidenceBundleManifest {
        schema_version: SCHEMA_VERSION,
        source: source.clone(),
        builder: builder.clone(),
        findings,
        replay_plans: replay_plans.clone(),
        artifacts: stored_artifacts.clone(),
        generated_files: generated_files.clone(),
    };
    let attestation = attestation(
        source,
        builder,
        &replay_plans,
        &stored_artifacts,
        &generated_files,
    );
    fs::write(
        root.join("attestation.json"),
        serde_json::to_vec_pretty(&attestation)?,
    )?;
    fs::write(
        root.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(manifest)
}

/// Writes the aggregate bundle produced by a real scan.
///
/// # Errors
/// Returns an error when report paths or replay metadata are unsafe, finding and
/// evidence references are inconsistent, serialization fails, or bundle files
/// cannot be created.
#[allow(clippy::too_many_arguments)]
pub fn write_run_bundle(
    root: &Path,
    source: SourceDescriptor,
    builder: BuilderDescriptor,
    mut findings: Vec<ReportFinding>,
    mut replay_plans: Vec<ReplayPlan>,
    events: &[RunEvent],
    artifacts: Vec<BundleArtifactInput>,
    report: &RunReport,
) -> Result<EvidenceBundleManifest, BundleError> {
    if replay_plans
        .iter()
        .flat_map(|plan| plan.environment.keys())
        .any(|name| sensitive_environment_name(name))
    {
        return Err(BundleError::SensitiveReplayEnvironment);
    }
    ensure_empty(root)?;
    fs::create_dir_all(root.join("artifacts"))?;
    fs::create_dir_all(root.join("reports"))?;
    findings.sort_by(|left, right| left.id.cmp(&right.id));
    replay_plans.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    unique_ids(&findings, &replay_plans)?;
    let stored_artifacts = write_artifacts(root, artifacts)?;
    validate_evidence_references(&findings, &stored_artifacts)?;
    let sarif = export_sarif(&findings);
    validate_sarif(&sarif)?;
    let sarif_bytes = serde_json::to_vec_pretty(&sarif)?;
    let findings_json = serde_json::to_vec_pretty(&findings)?;
    let replay_json = serde_json::to_vec_pretty(&replay_plans)?;
    let report_json = serde_json::to_vec_pretty(report)?;
    let markdown = run_markdown_summary(&source, &findings, report).into_bytes();
    let jsonl = run_events_jsonl(events)?;
    let mut generated_files = Vec::new();
    for (path, bytes) in [
        ("reports/results.sarif", sarif_bytes.as_slice()),
        ("reports/results.json", findings_json.as_slice()),
        ("reports/replay.json", replay_json.as_slice()),
        ("reports/run.json", report_json.as_slice()),
        ("reports/summary.md", markdown.as_slice()),
        ("events.jsonl", jsonl.as_slice()),
    ] {
        fs::write(root.join(path), bytes)?;
        generated_files.push(file_record(path, bytes));
    }
    let manifest = EvidenceBundleManifest {
        schema_version: SCHEMA_VERSION,
        source: source.clone(),
        builder: builder.clone(),
        findings,
        replay_plans: replay_plans.clone(),
        artifacts: stored_artifacts.clone(),
        generated_files: generated_files.clone(),
    };
    let attestation = attestation(
        source,
        builder,
        &replay_plans,
        &stored_artifacts,
        &generated_files,
    );
    fs::write(
        root.join("attestation.json"),
        serde_json::to_vec_pretty(&attestation)?,
    )?;
    fs::write(
        root.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(manifest)
}

/// Loads and verifies every digest in an evidence bundle without network access.
///
/// # Errors
/// Returns an error for missing, malformed, unsafe, unexpected, or tampered bundle files.
pub fn verify_bundle(root: &Path) -> Result<EvidenceBundleManifest, BundleError> {
    let manifest: EvidenceBundleManifest =
        serde_json::from_slice(&fs::read(root.join("manifest.json"))?)?;
    validate_evidence_references(&manifest.findings, &manifest.artifacts)?;
    let attestation: EvidenceAttestation =
        serde_json::from_slice(&fs::read(root.join("attestation.json"))?)?;
    let mut expected = BTreeMap::new();
    for artifact in &manifest.artifacts {
        expected.insert(
            artifact.relative_path.clone(),
            (artifact.sha256.clone(), artifact.size_bytes),
        );
    }
    for file in &manifest.generated_files {
        expected.insert(
            file.relative_path.clone(),
            (file.sha256.clone(), file.size_bytes),
        );
    }
    for (path, (digest, size)) in &expected {
        let bytes = fs::read(safe_join(root, path)?)?;
        if sha256(&bytes) != *digest
            || u64::try_from(bytes.len()).map_err(|_| BundleError::SizeOverflow)? != *size
        {
            return Err(BundleError::DigestMismatch(path.clone()));
        }
    }
    let subjects = attestation
        .subject
        .iter()
        .map(|subject| {
            let digest = subject.digest.get("sha256").cloned().unwrap_or_default();
            (subject.name.clone(), digest)
        })
        .collect::<BTreeMap<_, _>>();
    for (path, (digest, _)) in expected {
        if subjects.get(&path) != Some(&digest) {
            return Err(BundleError::AttestationMismatch(path));
        }
    }
    if attestation.predicate.source != manifest.source
        || attestation.predicate.builder != manifest.builder
    {
        return Err(BundleError::AttestationMetadata);
    }
    let commands = manifest
        .replay_plans
        .iter()
        .map(|plan| plan.command.clone())
        .collect::<Vec<_>>();
    let artifact_digests = manifest
        .artifacts
        .iter()
        .map(|item| (item.logical_name.clone(), item.sha256.clone()))
        .collect::<BTreeMap<_, _>>();
    if attestation.predicate.commands != commands
        || attestation.predicate.artifact_digests != artifact_digests
    {
        return Err(BundleError::AttestationMetadata);
    }
    validate_sarif(&serde_json::from_slice(&fs::read(
        root.join("reports/results.sarif"),
    )?)?)?;
    let report_findings: Vec<ReportFinding> =
        serde_json::from_slice(&fs::read(root.join("reports/results.json"))?)?;
    let report_plans: Vec<ReplayPlan> =
        serde_json::from_slice(&fs::read(root.join("reports/replay.json"))?)?;
    if report_findings != manifest.findings || report_plans != manifest.replay_plans {
        return Err(BundleError::ReportMismatch);
    }
    validate_sarif_agreement(root, &manifest.findings)?;
    Ok(manifest)
}

/// Replays a finding solely from verified bundle metadata.
///
/// # Errors
/// Returns an error for bundle integrity failures, unknown findings, unsafe source paths,
/// or sandbox execution failures.
pub async fn replay_finding(
    bundle_root: &Path,
    repository_root: &Path,
    finding_id: &str,
    backend: Arc<dyn SandboxBackend>,
    cancellation: CancellationToken,
) -> Result<ExperimentEvidence, BundleError> {
    let manifest = verify_bundle(bundle_root)?;
    let plan = manifest
        .replay_plans
        .iter()
        .find(|plan| plan.finding_id == finding_id)
        .ok_or_else(|| BundleError::UnknownFinding(finding_id.into()))?;
    let source_root = safe_join(repository_root, &plan.relative_source_root)?;
    let runner = ExperimentRunner::new(backend);
    runner
        .execute(
            ExperimentRequest {
                sandbox: SandboxRequest {
                    source_root,
                    image: plan.image.clone(),
                    command: plan.command.clone(),
                    environment: plan.environment.clone(),
                },
                oracle: plan.oracle.clone(),
                negative_control: plan.negative_control.clone(),
            },
            cancellation,
        )
        .await
        .map_err(BundleError::Replay)
}

fn ensure_empty(root: &Path) -> Result<(), BundleError> {
    if root.exists() && fs::read_dir(root)?.next().transpose()?.is_some() {
        return Err(BundleError::NotEmpty);
    }
    fs::create_dir_all(root)?;
    Ok(())
}

fn unique_ids(findings: &[ReportFinding], plans: &[ReplayPlan]) -> Result<(), BundleError> {
    let finding_ids = findings
        .iter()
        .map(|finding| finding.id.as_str())
        .collect::<BTreeSet<_>>();
    if finding_ids.len() != findings.len() {
        return Err(BundleError::DuplicateFinding);
    }
    if plans
        .iter()
        .any(|plan| !finding_ids.contains(plan.finding_id.as_str()))
    {
        return Err(BundleError::UnknownReplayPlan);
    }
    Ok(())
}

fn validate_evidence_references(
    findings: &[ReportFinding],
    artifacts: &[BundleArtifact],
) -> Result<(), BundleError> {
    let available = artifacts
        .iter()
        .map(|artifact| artifact.sha256.as_str())
        .collect::<BTreeSet<_>>();
    for digest in findings
        .iter()
        .flat_map(|finding| finding.evidence_digests.iter())
    {
        if !available.contains(digest.as_str()) {
            return Err(BundleError::MissingEvidence(digest.clone()));
        }
    }
    Ok(())
}

fn write_artifacts(
    root: &Path,
    artifacts: Vec<BundleArtifactInput>,
) -> Result<Vec<BundleArtifact>, BundleError> {
    let mut records = Vec::new();
    for artifact in artifacts {
        let digest = sha256(&artifact.bytes);
        let path = format!("artifacts/{digest}");
        let target = safe_join(root, &path)?;
        if target.exists() {
            if fs::read(&target)? != artifact.bytes {
                return Err(BundleError::DigestMismatch(path));
            }
        } else {
            fs::write(&target, &artifact.bytes)?;
        }
        records.push(BundleArtifact {
            logical_name: artifact.logical_name,
            media_type: artifact.media_type,
            relative_path: path,
            sha256: digest,
            size_bytes: u64::try_from(artifact.bytes.len())
                .map_err(|_| BundleError::SizeOverflow)?,
        });
    }
    records.sort_by(|left, right| {
        (&left.logical_name, &left.sha256).cmp(&(&right.logical_name, &right.sha256))
    });
    Ok(records)
}

fn file_record(path: &str, bytes: &[u8]) -> BundleFile {
    BundleFile {
        relative_path: path.into(),
        sha256: sha256(bytes),
        size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
    }
}

fn events_jsonl(events: &[InvestigationEvent]) -> Result<Vec<u8>, BundleError> {
    let mut bytes = Vec::new();
    for event in events {
        bytes.extend(serde_json::to_vec(event)?);
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn run_events_jsonl(events: &[RunEvent]) -> Result<Vec<u8>, BundleError> {
    let mut bytes = Vec::new();
    for event in events {
        bytes.extend(serde_json::to_vec(event)?);
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn markdown_summary(source: &SourceDescriptor, findings: &[ReportFinding]) -> String {
    let mut output = format!(
        "# Evidence-driven security report\n\nSource: `{}` at `{}`\n\n",
        source.repository, source.revision
    );
    append_findings(&mut output, findings);
    output
}

fn append_findings(output: &mut String, findings: &[ReportFinding]) {
    for finding in findings {
        let _ = write!(
            output,
            "## {}\n\n- Verdict: `{:?}`\n- Confidence: `{:?}`\n- Location: `{}:{}`\n- Rule: `{}`\n\n{}\n\n",
            finding.title,
            finding.verdict,
            finding.confidence,
            finding.relative_path,
            finding.start_line,
            finding.rule_id,
            finding.message
        );
    }
}

fn run_markdown_summary(
    source: &SourceDescriptor,
    findings: &[ReportFinding],
    report: &RunReport,
) -> String {
    let mut output = format!(
        "# Evidence-driven security report\n\nRun `{}` finished with status `{:?}`.\n\nSource: `{}` at `{}`\n\nSignals: {}  \nHypotheses: {}  \nExperiments: {}\n\n",
        report.run_id,
        report.status,
        source.repository,
        source.revision,
        report.signals.len(),
        report.hypotheses.len(),
        report.experiments.len()
    );
    if !report.limitations.is_empty() {
        output.push_str("## Limitations\n\n");
        for limitation in &report.limitations {
            let _ = writeln!(output, "- {limitation}");
        }
        output.push('\n');
    }
    if !report.failures.is_empty() {
        output.push_str("## Failures\n\n");
        for failure in &report.failures {
            let _ = writeln!(output, "- {failure}");
        }
        output.push('\n');
    }
    if findings.is_empty() {
        output.push_str("## Findings\n\nNo findings were produced.\n");
    } else {
        append_findings(&mut output, findings);
    }
    output
}

fn validate_sarif_agreement(root: &Path, findings: &[ReportFinding]) -> Result<(), BundleError> {
    let sarif: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("reports/results.sarif"))?)?;
    let results = sarif
        .pointer("/runs/0/results")
        .and_then(serde_json::Value::as_array)
        .ok_or(BundleError::ReportMismatch)?;
    let sarif_state = results
        .iter()
        .map(|result| {
            let id = result
                .pointer("/partialFingerprints/edsaFindingId")
                .and_then(serde_json::Value::as_str)
                .ok_or(BundleError::ReportMismatch)?;
            let verdict = result
                .pointer("/properties/edsa.verdict")
                .and_then(serde_json::Value::as_str)
                .ok_or(BundleError::ReportMismatch)?;
            Ok((id.to_owned(), verdict.to_owned()))
        })
        .collect::<Result<BTreeMap<_, _>, BundleError>>()?;
    let manifest_state = findings
        .iter()
        .map(|finding| {
            (
                finding.id.clone(),
                format!("{:?}", finding.verdict).to_ascii_lowercase(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if sarif_state != manifest_state {
        return Err(BundleError::ReportMismatch);
    }
    Ok(())
}

fn attestation(
    source: SourceDescriptor,
    builder: BuilderDescriptor,
    plans: &[ReplayPlan],
    artifacts: &[BundleArtifact],
    files: &[BundleFile],
) -> EvidenceAttestation {
    let subjects = artifacts
        .iter()
        .map(|item| (item.relative_path.clone(), item.sha256.clone()))
        .chain(
            files
                .iter()
                .map(|item| (item.relative_path.clone(), item.sha256.clone())),
        )
        .map(|(name, digest)| AttestationSubject {
            name,
            digest: BTreeMap::from([("sha256".into(), digest)]),
        })
        .collect::<Vec<_>>();
    let artifact_digests = artifacts
        .iter()
        .map(|item| (item.logical_name.clone(), item.sha256.clone()))
        .collect();
    EvidenceAttestation {
        statement_type: "https://in-toto.io/Statement/v1".into(),
        subject: subjects,
        predicate_type: "https://evidence-driven-security-agent.dev/attestation/v1".into(),
        predicate: AttestationPredicate {
            source,
            builder,
            commands: plans.iter().map(|plan| plan.command.clone()).collect(),
            artifact_digests,
        },
    }
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf, BundleError> {
    let relative = Path::new(relative);
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(BundleError::UnsafePath(relative.to_path_buf()));
    }
    Ok(root.join(relative))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Debug, Error)]
pub enum BundleError {
    #[error("sensitive environment variables cannot enter report or replay artifacts")]
    SensitiveReplayEnvironment,
    #[error("bundle directory is not empty")]
    NotEmpty,
    #[error("bundle contains a duplicate finding ID")]
    DuplicateFinding,
    #[error("replay plan references an unknown finding")]
    UnknownReplayPlan,
    #[error("finding was not found: {0}")]
    UnknownFinding(String),
    #[error("bundle path is unsafe: {0}")]
    UnsafePath(PathBuf),
    #[error("bundle digest or size mismatch: {0}")]
    DigestMismatch(String),
    #[error("bundle is missing referenced evidence artifact: {0}")]
    MissingEvidence(String),
    #[error("attestation subject mismatch: {0}")]
    AttestationMismatch(String),
    #[error("attestation source or builder metadata does not match")]
    AttestationMetadata,
    #[error("bundle reports disagree on finding IDs, verdicts, or replay metadata")]
    ReportMismatch,
    #[error("bundle size cannot be represented")]
    SizeOverflow,
    #[error("bundle I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("bundle JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("bundle SARIF failed validation: {0}")]
    Sarif(#[from] crate::SarifValidationError),
    #[error("finding replay failed: {0}")]
    Replay(#[from] edsa_adapter_sdk::AdapterError),
}
