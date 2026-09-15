use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use edsa_agent_runtime::{
    AgentRuntime, EvidenceDocument, FileSummary, GateExecution, PatchAgentContract,
    PatchAgentInput, PatchDecision, PatchGateExecutor, PatchValidationPolicy, RepositoryDocument,
    ReviewerContract, ReviewerInput, RuntimeBudget, VerificationLadder, VerificationPolicy,
    fingerprint_repository, run_patch_attempt, validate_unified_diff,
};
use edsa_core::{
    EvidenceId, EvidenceRef, Hypothesis, HypothesisId, OracleKind, PatchAttemptId,
    PatchAttemptRecord, PatchAttemptStatus, PatchGate, RepositoryPolicy, SCHEMA_VERSION, Verdict,
    ingest_repository,
};
use edsa_model_providers::ConfiguredProvider;
use edsa_reporting::{EvidenceBundleManifest, ReplayPlan};
use edsa_sandbox::{DockerRunner, SandboxOutput, SandboxPolicy, SandboxRequest};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::run_report;

const MAXIMUM_PATCH_BYTES: usize = 256 * 1024;

#[path = "patch_commands.rs"]
mod commands;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PatchArguments {
    pub run_directory: PathBuf,
    pub finding_id: String,
    pub approved: bool,
    pub maximum_attempts: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PatchOutcome {
    pub finding_id: String,
    pub status: PatchAttemptStatus,
    pub attempts: Vec<PatchAttemptRecord>,
    pub rejected_proposals: Vec<String>,
    pub proposal_directory: PathBuf,
    pub original_before_sha256: String,
    pub original_after_sha256: String,
}

#[derive(Debug, Serialize)]
struct StoredProposal<'a> {
    attempt_id: &'a str,
    rationale: &'a str,
    suggested_tests: &'a [Vec<String>],
    input_tokens: u64,
    output_tokens: u64,
    total_tokens: u64,
    estimated_cost_microusd: u64,
    provider_request_id: &'a Option<String>,
    validation_error: Option<&'a str>,
}

struct AttemptContext<'a> {
    runtime: &'a AgentRuntime,
    repository: &'a Path,
    finding: &'a edsa_reporting::ReportFinding,
    plan: &'a ReplayPlan,
    relevant_files: &'a [FileSummary],
    relevant_documents: &'a [RepositoryDocument],
    evidence: &'a [EvidenceRef],
    evidence_documents: &'a [EvidenceDocument],
    proposal_directory: &'a Path,
    allowed_paths: &'a BTreeSet<PathBuf>,
    required_path: &'a Path,
    cancellation: &'a CancellationToken,
}

#[must_use]
pub fn usage() -> &'static str {
    "usage: edsa patch <run-directory> <finding-id> --approve [--maximum-attempts <1|2>]"
}

/// Parses an explicitly approved patch workflow.
///
/// # Errors
/// Returns an error for missing, unsafe, duplicate, or unknown arguments.
pub fn parse(arguments: Vec<String>) -> Result<PatchArguments, PatchError> {
    let mut arguments = arguments.into_iter();
    let run_directory = PathBuf::from(arguments.next().ok_or(PatchError::Usage)?);
    let finding_id = arguments.next().ok_or(PatchError::Usage)?;
    safe_identifier(&finding_id)?;
    let mut approved = false;
    let mut maximum_attempts = 2;
    let mut attempts_seen = false;
    while let Some(option) = arguments.next() {
        match option.as_str() {
            "--approve" if !approved => approved = true,
            "--maximum-attempts" if !attempts_seen => {
                let value = arguments
                    .next()
                    .ok_or_else(|| PatchError::MissingValue(option.clone()))?;
                maximum_attempts = value.parse().map_err(|_| PatchError::InvalidAttempts)?;
                if !(1..=2).contains(&maximum_attempts) {
                    return Err(PatchError::InvalidAttempts);
                }
                attempts_seen = true;
            }
            "--approve" | "--maximum-attempts" => {
                return Err(PatchError::DuplicateOption(option));
            }
            _ => return Err(PatchError::UnknownOption(option)),
        }
    }
    if !approved {
        return Err(PatchError::ApprovalRequired);
    }
    Ok(PatchArguments {
        run_directory,
        finding_id,
        approved,
        maximum_attempts,
    })
}

/// Requests a real hosted-model patch and verifies it in disposable worktrees.
///
/// # Errors
/// Returns an error when the run is invalid, the finding is not confirmed, the
/// model proposal is unsafe, or durable attempt records cannot be written.
pub async fn execute(
    arguments: PatchArguments,
    cancellation: CancellationToken,
) -> Result<PatchOutcome, PatchError> {
    if !arguments.approved {
        return Err(PatchError::ApprovalRequired);
    }
    let manifest = run_report::verify_run(&arguments.run_directory)?;
    let finding = manifest
        .findings
        .iter()
        .find(|finding| finding.id == arguments.finding_id)
        .ok_or_else(|| PatchError::FindingNotFound(arguments.finding_id.clone()))?;
    if finding.verdict != Verdict::Confirmed {
        return Err(PatchError::FindingNotConfirmed(arguments.finding_id));
    }
    let plan = manifest
        .replay_plans
        .iter()
        .find(|plan| plan.finding_id == finding.id)
        .cloned()
        .ok_or_else(|| PatchError::ReplayPlanMissing(finding.id.clone()))?;
    let repository = run_report::repository_path(&arguments.run_directory)?
        .ok_or(PatchError::RunDirectoryRequired)?;
    let repository = dunce::canonicalize(repository)?;
    let inventory = ingest_repository(&repository, &RepositoryPolicy::default())?;
    let required_path = PathBuf::from(&finding.relative_path);
    let allowed_paths = inventory
        .files
        .iter()
        .map(|file| PathBuf::from(&file.relative_path))
        .collect::<BTreeSet<_>>();
    if !allowed_paths.contains(&required_path) {
        return Err(PatchError::FindingPathNotAdmitted(required_path));
    }

    let provider = Arc::new(ConfiguredProvider::from_environment()?);
    let model = provider.model().to_owned();
    let runtime = AgentRuntime::new(
        provider,
        model,
        RuntimeBudget {
            maximum_turns: u64::from(arguments.maximum_attempts) * 4,
            maximum_wall_time_seconds: 1_800,
            maximum_model_tokens: 160_000,
            maximum_cost_microusd: 2_000_000,
            maximum_experiments: 0,
            maximum_concurrency: 1,
        },
    );
    let (relevant_files, relevant_documents) =
        relevant_files(&repository, &inventory, &finding.relative_path)?;
    let evidence = evidence_references(&manifest, finding);
    let evidence_documents = evidence_documents(&arguments.run_directory, &manifest, finding)?;
    let proposal_root = arguments.run_directory.join("patches").join(&finding.id);
    fs::create_dir_all(&proposal_root)?;
    let prior_session_feedback = prior_session_feedback(&proposal_root)?;
    let proposal_directory = create_patch_session(&proposal_root)?;
    let before = fingerprint_repository(&repository)?;
    let (attempts, rejected_proposals) = run_attempts(
        &AttemptContext {
            runtime: &runtime,
            repository: &repository,
            finding,
            plan: &plan,
            relevant_files: &relevant_files,
            relevant_documents: &relevant_documents,
            evidence: &evidence,
            evidence_documents: &evidence_documents,
            proposal_directory: &proposal_directory,
            allowed_paths: &allowed_paths,
            required_path: &required_path,
            cancellation: &cancellation,
        },
        arguments.maximum_attempts,
        prior_session_feedback,
    )
    .await?;
    let after = fingerprint_repository(&repository)?;
    if before != after {
        return Err(PatchError::OriginalRepositoryChanged);
    }
    let status = attempts
        .last()
        .map_or(PatchAttemptStatus::Failed, |attempt| attempt.status);
    let outcome = PatchOutcome {
        finding_id: finding.id.clone(),
        status,
        attempts,
        rejected_proposals,
        proposal_directory,
        original_before_sha256: before.status_sha256,
        original_after_sha256: after.status_sha256,
    };
    fs::write(
        outcome.proposal_directory.join("outcome.json"),
        serde_json::to_vec_pretty(&outcome)?,
    )?;
    Ok(outcome)
}

fn create_patch_session(root: &Path) -> Result<PathBuf, PatchError> {
    for sequence in 1..=9_999_u16 {
        let path = root.join(format!("session-{sequence:04}"));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(PatchError::PatchSessionLimit)
}

async fn run_attempts(
    context: &AttemptContext<'_>,
    maximum_attempts: u8,
    mut feedback: Vec<String>,
) -> Result<(Vec<PatchAttemptRecord>, Vec<String>), PatchError> {
    let mut attempts = Vec::new();
    let mut rejected = Vec::new();
    for attempt_number in 1..=maximum_attempts {
        let proposal = context
            .runtime
            .execute::<PatchAgentContract>(
                &patch_input(context, feedback.clone()),
                0,
                context.cancellation,
            )
            .await?;
        let patch = proposal.output.unified_diff.as_bytes();
        let validation = validate_unified_diff(
            patch,
            &PatchValidationPolicy {
                maximum_bytes: MAXIMUM_PATCH_BYTES,
                allowed_paths: context.allowed_paths.clone(),
                required_path: context.required_path.to_path_buf(),
            },
        );
        let attempt_id = format!("{}-{attempt_number}", context.finding.id);
        let validation_error = validation.as_ref().err().map(ToString::to_string);
        fs::write(
            context
                .proposal_directory
                .join(format!("{attempt_id}.diff")),
            patch,
        )?;
        fs::write(
            context
                .proposal_directory
                .join(format!("{attempt_id}-proposal.json")),
            serde_json::to_vec_pretty(&StoredProposal {
                attempt_id: &attempt_id,
                rationale: &proposal.output.rationale,
                suggested_tests: &proposal.output.tests_to_run,
                input_tokens: proposal.usage.input_tokens,
                output_tokens: proposal.usage.output_tokens,
                total_tokens: proposal.usage.total_tokens,
                estimated_cost_microusd: proposal.estimated_cost_microusd,
                provider_request_id: &proposal.provider_request_id,
                validation_error: validation_error.as_deref(),
            })?,
        )?;
        if let Some(error) = validation_error {
            feedback = vec![format!("Rejected proposal: {error}")];
            rejected.push(error);
            continue;
        }
        let executor = LivePatchGates::new(
            context.plan.clone(),
            context.finding.rule_id.clone(),
            context.finding.relative_path.clone(),
            proposal.output.tests_to_run.clone(),
            commands::go_sources(context.repository, context.plan),
        );
        let ladder = VerificationLadder::new(
            executor,
            VerificationPolicy {
                maximum_variant_cases: 8,
            },
        )?;
        let record = run_patch_attempt(
            context.repository,
            PatchAttemptId::new(&attempt_id),
            patch,
            PatchDecision::Approved,
            &ladder,
            context.cancellation,
        )
        .await?;
        fs::write(
            context
                .proposal_directory
                .join(format!("{attempt_id}.json")),
            serde_json::to_vec_pretty(&record)?,
        )?;
        let verified = record.status == PatchAttemptStatus::Verified;
        feedback.extend(failed_gate_feedback(&record));
        attempts.push(record);
        if verified || context.cancellation.is_cancelled() {
            break;
        }
        if attempt_number < maximum_attempts {
            feedback = review_failed_attempt(
                context,
                &attempt_id,
                &proposal.output.unified_diff,
                feedback,
            )
            .await?;
        }
    }
    Ok((attempts, rejected))
}

fn prior_session_feedback(proposal_root: &Path) -> Result<Vec<String>, PatchError> {
    let mut sessions = fs::read_dir(proposal_root)?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|file_type| file_type.is_dir()))
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    sessions.sort();

    let mut feedback = BTreeSet::new();
    for session in sessions {
        let outcome_path = session.join("outcome.json");
        if !outcome_path.is_file() {
            continue;
        }
        let outcome: serde_json::Value = serde_json::from_slice(&fs::read(outcome_path)?)?;
        for rejected in outcome["rejected_proposals"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
        {
            feedback.insert(format!("Prior proposal was rejected: {rejected}."));
        }
        for gate in outcome["attempts"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|attempt| attempt["gates"].as_array().into_iter().flatten())
            .filter(|gate| gate["outcome"].as_str() == Some("failed"))
        {
            let name = gate["gate"].as_str().unwrap_or("unknown gate");
            let summary = gate["summary"].as_str().unwrap_or("no summary");
            if name == "variant_search" && summary.contains("Candidate returned without rejecting")
            {
                feedback.insert(
                    "Mandatory repair requirement from a prior attempt: a symbolic-link path inside the application directory reached a target outside it. A lexical path check alone is insufficient; reject paths whose resolved filesystem target is outside the application directory before reading.".into(),
                );
            } else {
                feedback.insert(format!("Prior {name} gate failed: {summary}"));
            }
        }
    }
    Ok(feedback.into_iter().take(12).collect())
}

fn failed_gate_feedback(record: &PatchAttemptRecord) -> Vec<String> {
    record
        .gates
        .iter()
        .filter(|gate| gate.outcome == edsa_core::GateOutcome::Failed)
        .map(|gate| format!("{:?}: {}", gate.gate, gate.summary))
        .collect()
}

async fn review_failed_attempt(
    context: &AttemptContext<'_>,
    attempt_id: &str,
    diff: &str,
    mut feedback: Vec<String>,
) -> Result<Vec<String>, PatchError> {
    let review = context
        .runtime
        .execute::<ReviewerContract>(
            &ReviewerInput {
                hypothesis_id: HypothesisId::new(&context.finding.id),
                evidence: context.evidence.to_vec(),
                proposed_diff: Some(diff.to_owned()),
                completed_gate_names: feedback.clone(),
            },
            0,
            context.cancellation,
        )
        .await?;
    feedback.extend(review.output.concerns.clone());
    feedback.extend(review.output.requested_experiments.clone());
    fs::write(
        context
            .proposal_directory
            .join(format!("{attempt_id}-review.json")),
        serde_json::to_vec_pretty(&review.output)?,
    )?;
    Ok(feedback)
}

fn patch_input(context: &AttemptContext<'_>, feedback: Vec<String>) -> PatchAgentInput {
    PatchAgentInput {
        hypothesis: Hypothesis {
            schema_version: SCHEMA_VERSION,
            id: HypothesisId::new(&context.finding.id),
            title: context.finding.title.clone(),
            claim: context.finding.message.clone(),
            weakness: context.finding.rule_id.clone(),
            signal_ids: Vec::new(),
        },
        confirmation_evidence: context.evidence.to_vec(),
        confirmation_artifacts: context.evidence_documents.to_vec(),
        relevant_files: context.relevant_files.to_vec(),
        relevant_documents: context.relevant_documents.to_vec(),
        prior_attempt_feedback: feedback,
    }
}

fn relevant_files(
    repository: &Path,
    inventory: &edsa_core::RepositoryInventory,
    required: &str,
) -> Result<(Vec<FileSummary>, Vec<RepositoryDocument>), PatchError> {
    const MAXIMUM_SOURCE_BYTES: usize = 64 * 1024;
    let mut ordered = inventory.files.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|file| (file.relative_path != required, file.relative_path.clone()));
    let mut summaries = Vec::with_capacity(ordered.len());
    let mut documents = Vec::new();
    let mut remaining = MAXIMUM_SOURCE_BYTES;
    for file in ordered {
        let bytes = fs::read(repository.join(&file.relative_path))?;
        summaries.push(FileSummary {
            relative_path: file.relative_path.clone(),
            sha256: format!("{:x}", Sha256::digest(&bytes)),
            size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        });
        if remaining == 0 {
            continue;
        }
        let visible_bytes = bytes.len().min(remaining);
        documents.push(RepositoryDocument {
            relative_path: file.relative_path.clone(),
            content: String::from_utf8_lossy(&bytes[..visible_bytes]).into_owned(),
            truncated: visible_bytes < bytes.len(),
        });
        remaining = remaining.saturating_sub(visible_bytes);
    }
    Ok((summaries, documents))
}

fn evidence_references(
    manifest: &EvidenceBundleManifest,
    finding: &edsa_reporting::ReportFinding,
) -> Vec<EvidenceRef> {
    manifest
        .artifacts
        .iter()
        .filter(|artifact| finding.evidence_digests.contains(&artifact.sha256))
        .map(|artifact| EvidenceRef {
            schema_version: SCHEMA_VERSION,
            id: EvidenceId::new(format!("evidence-{}", &artifact.sha256[..16])),
            media_type: artifact.media_type.clone(),
            sha256: artifact.sha256.clone(),
            size_bytes: artifact.size_bytes,
        })
        .collect()
}

fn evidence_documents(
    run_directory: &Path,
    manifest: &EvidenceBundleManifest,
    finding: &edsa_reporting::ReportFinding,
) -> Result<Vec<EvidenceDocument>, PatchError> {
    const MAXIMUM_EVIDENCE_BYTES: usize = 48 * 1024;
    manifest
        .artifacts
        .iter()
        .filter(|artifact| finding.evidence_digests.contains(&artifact.sha256))
        .map(|artifact| {
            let bytes =
                fs::read(run_report::bundle_path(run_directory).join(&artifact.relative_path))?;
            let visible = &bytes[..bytes.len().min(MAXIMUM_EVIDENCE_BYTES)];
            Ok(EvidenceDocument {
                logical_name: artifact.logical_name.clone(),
                media_type: artifact.media_type.clone(),
                sha256: artifact.sha256.clone(),
                content: String::from_utf8_lossy(visible).into_owned(),
                truncated: bytes.len() > MAXIMUM_EVIDENCE_BYTES,
            })
        })
        .collect()
}

#[derive(Debug)]
struct LivePatchGates {
    plan: ReplayPlan,
    finding_rule: String,
    finding_path: String,
    runner: DockerRunner,
    go_sources: Result<String, String>,
}

impl LivePatchGates {
    fn new(
        plan: ReplayPlan,
        finding_rule: String,
        finding_path: String,
        _proposed_tests: Vec<Vec<String>>,
        go_sources: Result<String, String>,
    ) -> Self {
        let mut policy = SandboxPolicy::default();
        policy
            .allowed_environment
            .extend(plan.environment.keys().cloned());
        policy
            .allowed_environment
            .insert("EDSA_NEGATIVE_CONTROL".into());
        policy
            .allowed_environment
            .insert("EDSA_VARIANT_INDEX".into());
        plan.sandbox_policy.apply_to(&mut policy);
        if plan
            .command
            .first()
            .is_some_and(|program| program == "node")
        {
            policy.tmpfs_size = "512m".into();
        }
        Self {
            plan,
            finding_rule,
            finding_path,
            runner: DockerRunner::new(policy),
            go_sources,
        }
    }

    async fn run(
        &self,
        worktree: &Path,
        command: Vec<String>,
        environment: BTreeMap<String, String>,
        cancellation: CancellationToken,
    ) -> Result<SandboxOutput, String> {
        self.runner
            .run(
                SandboxRequest {
                    source_root: worktree.join(&self.plan.relative_source_root),
                    image: commands::image(&self.plan),
                    command,
                    environment,
                },
                cancellation,
            )
            .await
            .map_err(|error| error.to_string())
    }
}

#[async_trait]
impl PatchGateExecutor for LivePatchGates {
    async fn execute(
        &self,
        worktree: &Path,
        gate: PatchGate,
        variant_index: Option<u32>,
        cancellation: CancellationToken,
    ) -> GateExecution {
        if gate == PatchGate::StaticRescan {
            return self.static_rescan(worktree);
        }
        let command = match gate {
            PatchGate::BuildBaseline => build_command(&self.plan.image),
            PatchGate::Regression => regression_command(&self.plan.image),
            PatchGate::OriginalProofStopped | PatchGate::Replay | PatchGate::VariantSearch => {
                match commands::verification(
                    &self.plan,
                    &self.finding_rule,
                    gate,
                    variant_index,
                    &self.go_sources,
                ) {
                    Ok(command) => command,
                    Err(reason) => return unavailable_gate(&reason),
                }
            }
            _ => self.plan.command.clone(),
        };
        let mut environment = self.plan.environment.clone();
        if gate == PatchGate::NegativeControl {
            environment.insert("EDSA_NEGATIVE_CONTROL".into(), "1".into());
        }
        if let Some(index) = variant_index {
            environment.insert("EDSA_VARIANT_INDEX".into(), index.to_string());
        }
        match self
            .run(worktree, command.clone(), environment, cancellation)
            .await
        {
            Ok(output) => {
                let passed = self.gate_passed(gate, &output);
                GateExecution {
                    command,
                    exit_code: Some(i32::from(!passed)),
                    stdout: output.stdout,
                    stderr: output.stderr,
                }
            }
            Err(error) => GateExecution {
                command,
                exit_code: Some(1),
                stdout: Vec::new(),
                stderr: error.into_bytes(),
            },
        }
    }
}

fn build_command(image: &str) -> Vec<String> {
    if image.contains("python") {
        vec![
            "python".into(),
            "-c".into(),
            "import pathlib; [compile(p.read_text(encoding='utf-8'), str(p), 'exec') for p in pathlib.Path('.').rglob('*.py')]".into(),
        ]
    } else if image.contains("golang") || image.contains("go:") {
        vec![
            "go".into(),
            "test".into(),
            "./...".into(),
            "-run".into(),
            "^$".into(),
        ]
    } else {
        regression_command(image)
    }
}

fn regression_command(image: &str) -> Vec<String> {
    if image.contains("python") {
        ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"]
            .map(str::to_owned)
            .to_vec()
    } else if image.contains("golang") || image.contains("go:") {
        ["go", "test", "./...", "-count=1"]
            .map(str::to_owned)
            .to_vec()
    } else {
        vec![
            "node".into(),
            "--input-type=module".into(),
            "--eval".into(),
            include_str!("node_patch_regression.mjs").into(),
        ]
    }
}

fn unavailable_gate(reason: &str) -> GateExecution {
    GateExecution {
        command: Vec::new(),
        exit_code: None,
        stdout: Vec::new(),
        stderr: reason.as_bytes().to_vec(),
    }
}

impl LivePatchGates {
    fn gate_passed(&self, gate: PatchGate, output: &SandboxOutput) -> bool {
        if output.exit_code != Some(0) || output.stdout_truncated || output.stderr_truncated {
            return false;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        match gate {
            PatchGate::OriginalProofStopped | PatchGate::Replay => {
                !oracle_matches(&self.plan.oracle, output)
                    && stdout.lines().any(|line| line == "EDSA_PATCH_BLOCKED")
            }
            PatchGate::VariantSearch => stdout.lines().any(|line| line == "EDSA_VARIANT_BLOCKED"),
            PatchGate::NegativeControl => oracle_matches(&self.plan.negative_control, output),
            _ => true,
        }
    }

    fn static_rescan(&self, worktree: &Path) -> GateExecution {
        let result = ingest_repository(worktree, &RepositoryPolicy::default())
            .map_err(|error| error.to_string())
            .and_then(|inventory| {
                edsa_signal_import::collect_builtin_signals(worktree, &inventory)
                    .map_err(|error| error.to_string())
            });
        match result {
            Ok(signals) => {
                let remains = signals.iter().any(|signal| {
                    signal.rule == self.finding_rule && signal.relative_path == self.finding_path
                });
                GateExecution {
                    command: vec!["edsa".into(), "built-in-rescan".into()],
                    exit_code: Some(i32::from(remains)),
                    stdout: serde_json::to_vec(&signals).unwrap_or_default(),
                    stderr: Vec::new(),
                }
            }
            Err(error) => GateExecution {
                command: vec!["edsa".into(), "built-in-rescan".into()],
                exit_code: Some(1),
                stdout: Vec::new(),
                stderr: error.into_bytes(),
            },
        }
    }
}

fn oracle_matches(oracle: &edsa_adapter_sdk::Oracle, output: &SandboxOutput) -> bool {
    match &oracle.kind {
        OracleKind::ExitCode => oracle
            .expected
            .parse::<i32>()
            .is_ok_and(|expected| output.exit_code == Some(expected)),
        OracleKind::StderrPattern => {
            String::from_utf8_lossy(&output.stderr).contains(&oracle.expected)
        }
        OracleKind::StdoutPattern
        | OracleKind::FileSystemBoundary
        | OracleKind::NetworkCallback
        | OracleKind::TestAssertion => {
            String::from_utf8_lossy(&output.stdout).contains(&oracle.expected)
        }
    }
}

fn safe_identifier(value: &str) -> Result<(), PatchError> {
    if value.is_empty() || value == "." || value == ".." || value.contains(['/', '\\']) {
        Err(PatchError::UnsafeFindingId)
    } else {
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum PatchError {
    #[error("usage: edsa patch <run-directory> <finding-id> --approve [--maximum-attempts <1|2>]")]
    Usage,
    #[error("patch verification requires --approve")]
    ApprovalRequired,
    #[error("finding ID contains unsafe path characters")]
    UnsafeFindingId,
    #[error("missing value for {0}")]
    MissingValue(String),
    #[error("duplicate option: {0}")]
    DuplicateOption(String),
    #[error("unknown option: {0}")]
    UnknownOption(String),
    #[error("maximum attempts must be 1 or 2")]
    InvalidAttempts,
    #[error("finding was not found: {0}")]
    FindingNotFound(String),
    #[error("patch generation is allowed only for confirmed findings: {0}")]
    FindingNotConfirmed(String),
    #[error("confirmed finding has no replay plan: {0}")]
    ReplayPlanMissing(String),
    #[error("patch requires a durable run directory, not a standalone bundle")]
    RunDirectoryRequired,
    #[error("finding path is outside the admitted repository: {0}")]
    FindingPathNotAdmitted(PathBuf),
    #[error("the original repository changed during patch verification")]
    OriginalRepositoryChanged,
    #[error("patch session limit reached for this finding")]
    PatchSessionLimit,
    #[error(transparent)]
    Report(#[from] run_report::RunReportError),
    #[error(transparent)]
    Provider(#[from] edsa_model_providers::ProviderError),
    #[error(transparent)]
    Runtime(#[from] edsa_agent_runtime::RuntimeError),
    #[error(transparent)]
    PatchLoop(#[from] edsa_agent_runtime::PatchLoopError),
    #[error(transparent)]
    Verification(#[from] edsa_agent_runtime::VerificationError),
    #[error(transparent)]
    Repository(#[from] edsa_core::RepositoryError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::{PatchError, parse, prior_session_feedback};

    #[test]
    fn patch_requires_an_explicit_decision() {
        let error = parse(vec!["run".into(), "finding-1".into()]).unwrap_err();
        assert!(matches!(error, PatchError::ApprovalRequired));
    }

    #[test]
    fn patch_parser_bounds_retries_and_rejects_unsafe_ids() {
        assert!(
            parse(vec![
                "run".into(),
                "finding-1".into(),
                "--approve".into(),
                "--maximum-attempts".into(),
                "2".into(),
            ])
            .is_ok()
        );
        assert!(parse(vec!["run".into(), "../finding".into(), "--approve".into()]).is_err());
        assert!(
            parse(vec![
                "run".into(),
                "finding".into(),
                "--approve".into(),
                "--maximum-attempts".into(),
                "3".into()
            ])
            .is_err()
        );
    }

    #[test]
    fn later_patch_sessions_receive_failed_variant_requirements() {
        let root = tempfile::tempdir().unwrap();
        let session = root.path().join("session-0001");
        std::fs::create_dir(&session).unwrap();
        std::fs::write(
            session.join("outcome.json"),
            r#"{
                "rejected_proposals": ["patch has a malformed diff header"],
                "attempts": [{
                    "gates": [{
                        "gate": "variant_search",
                        "outcome": "failed",
                        "summary": "Candidate returned without rejecting the path"
                    }]
                }]
            }"#,
        )
        .unwrap();

        let feedback = prior_session_feedback(root.path()).unwrap();
        assert!(
            feedback
                .iter()
                .any(|item| item.contains("symbolic-link path"))
        );
        assert!(
            feedback
                .iter()
                .any(|item| item.contains("malformed diff header"))
        );
    }
}
