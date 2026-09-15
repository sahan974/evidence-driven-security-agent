use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use edsa_core::{
    GateOutcome, PatchAttemptId, PatchAttemptRecord, PatchAttemptStatus, PatchGate,
    PatchGateEvidence, PatchVerification, SCHEMA_VERSION,
};
use sha2::{Digest, Sha256};
use tempfile::{Builder, NamedTempFile};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::{PatchGateExecutor, VerificationLadder};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PatchDecision {
    Denied,
    Approved,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryFingerprint {
    pub status_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PatchValidationPolicy {
    pub maximum_bytes: usize,
    pub allowed_paths: std::collections::BTreeSet<PathBuf>,
    pub required_path: PathBuf,
}

/// Validates the structural and repository scope of an untrusted unified diff.
///
/// # Errors
/// Returns an error for malformed, oversized, binary, path-traversing, or unrelated patches.
pub fn validate_unified_diff(
    patch: &[u8],
    policy: &PatchValidationPolicy,
) -> Result<(), PatchLoopError> {
    if patch.len() > policy.maximum_bytes {
        return Err(PatchLoopError::PatchTooLarge {
            actual: patch.len(),
            limit: policy.maximum_bytes,
        });
    }
    let text = std::str::from_utf8(patch).map_err(|_| PatchLoopError::NonUtf8Patch)?;
    if text.contains("GIT binary patch") || text.contains("Binary files ") {
        return Err(PatchLoopError::BinaryPatch);
    }
    for line in text.lines().filter(|line| line.starts_with("@@")) {
        if !is_unified_hunk_header(line) {
            return Err(PatchLoopError::MalformedPatchHeader);
        }
    }
    let mut changed = std::collections::BTreeSet::new();
    for line in text.lines().filter(|line| line.starts_with("diff --git ")) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 4 {
            return Err(PatchLoopError::MalformedPatchHeader);
        }
        let before = diff_path(fields[2], "a/")?;
        let after = diff_path(fields[3], "b/")?;
        if before != after {
            return Err(PatchLoopError::FileCreationOrDeletion);
        }
        if !policy.allowed_paths.contains(&after) {
            return Err(PatchLoopError::PatchPathNotAdmitted(after));
        }
        changed.insert(after);
    }
    let mut before_path = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("--- ") {
            before_path = Some(patch_file_header(value, "a/", policy)?);
        } else if let Some(value) = line.strip_prefix("+++ ") {
            let after_path = patch_file_header(value, "b/", policy)?;
            let before_path = before_path
                .take()
                .ok_or(PatchLoopError::MalformedPatchHeader)?;
            if before_path != after_path {
                return Err(PatchLoopError::FileCreationOrDeletion);
            }
            changed.insert(after_path);
        }
    }
    if before_path.is_some() {
        return Err(PatchLoopError::MalformedPatchHeader);
    }
    if changed.is_empty() {
        return Err(PatchLoopError::MissingPatchHeader);
    }
    if !changed.contains(&policy.required_path) {
        return Err(PatchLoopError::UnrelatedPatch(policy.required_path.clone()));
    }
    Ok(())
}

fn is_unified_hunk_header(line: &str) -> bool {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    matches!(fields.as_slice(), ["@@", before, after, "@@", ..] if is_hunk_range(before, '-') && is_hunk_range(after, '+'))
}

fn is_hunk_range(value: &str, prefix: char) -> bool {
    let Some(value) = value.strip_prefix(prefix) else {
        return false;
    };
    let mut values = value.split(',');
    let Some(start) = values.next() else {
        return false;
    };
    if start.is_empty() || !start.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    match values.next() {
        Some(count) if count.is_empty() || !count.bytes().all(|byte| byte.is_ascii_digit()) => {
            false
        }
        Some(_) => values.next().is_none(),
        None => true,
    }
}

fn patch_file_header(
    value: &str,
    prefix: &str,
    policy: &PatchValidationPolicy,
) -> Result<PathBuf, PatchLoopError> {
    let value = value
        .split_whitespace()
        .next()
        .ok_or(PatchLoopError::MalformedPatchHeader)?;
    if value == "/dev/null" {
        return Err(PatchLoopError::FileCreationOrDeletion);
    }
    let header_path = diff_path(value, prefix)?;
    if !policy.allowed_paths.contains(&header_path) {
        return Err(PatchLoopError::PatchPathNotAdmitted(header_path));
    }
    Ok(header_path)
}

fn diff_path(value: &str, prefix: &str) -> Result<PathBuf, PatchLoopError> {
    let value = value
        .strip_prefix(prefix)
        .ok_or(PatchLoopError::MalformedPatchHeader)?;
    let path = Path::new(value);
    if value.is_empty()
        || value.contains('\\')
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
        || path.starts_with(".git")
    {
        return Err(PatchLoopError::UnsafePatchPath(value.into()));
    }
    Ok(path.to_path_buf())
}

#[derive(Debug)]
pub struct DisposableWorktree {
    repository: PathBuf,
    path: PathBuf,
    original: RepositoryFingerprint,
    cleaned: bool,
}

impl DisposableWorktree {
    /// Creates a detached disposable Git worktree at the repository's current HEAD.
    ///
    /// # Errors
    /// Returns an error for invalid repository paths, Git failures, or temporary-path failures.
    pub fn create(repository: &Path) -> Result<Self, PatchLoopError> {
        let repository = dunce::canonicalize(repository)?;
        if !repository.is_dir() {
            return Err(PatchLoopError::NotDirectory);
        }
        let original = fingerprint_repository(&repository)?;
        let parent = repository.parent().ok_or(PatchLoopError::MissingParent)?;
        let temporary = Builder::new().prefix("edsa-worktree-").tempdir_in(parent)?;
        let path = temporary.path().to_path_buf();
        temporary.close()?;
        git_success(
            &repository,
            &[
                "-c",
                "core.autocrlf=false",
                "worktree",
                "add",
                "--detach",
                path_text(&path)?,
                "HEAD",
            ],
        )?;
        Ok(Self {
            repository,
            path,
            original,
            cleaned: false,
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Applies a unified diff only to the disposable worktree.
    ///
    /// # Errors
    /// Returns an error when the patch is invalid or cannot be applied.
    pub fn apply_patch(&self, patch: &[u8]) -> Result<(), PatchLoopError> {
        let mut file = NamedTempFile::new()?;
        std::io::Write::write_all(&mut file, patch)?;
        let patch_path = path_text(file.path())?;
        git_success(&self.path, &["apply", "--recount", "--check", patch_path])?;
        git_success(
            &self.path,
            &["apply", "--recount", "--whitespace=nowarn", patch_path],
        )
    }

    /// Removes the disposable worktree and proves the original tree is unchanged.
    ///
    /// # Errors
    /// Returns an error if cleanup fails or the original tree fingerprint changes.
    pub fn cleanup(mut self) -> Result<(), PatchLoopError> {
        git_success(
            &self.repository,
            &["worktree", "remove", "--force", path_text(&self.path)?],
        )?;
        self.cleaned = true;
        let after = fingerprint_repository(&self.repository)?;
        if after != self.original {
            return Err(PatchLoopError::OriginalTreeChanged);
        }
        Ok(())
    }
}

impl Drop for DisposableWorktree {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = Command::new("git")
                .arg("-C")
                .arg(&self.repository)
                .args(["worktree", "remove", "--force"])
                .arg(&self.path)
                .output();
        }
    }
}

/// Runs one patch attempt and always cleans its disposable worktree.
///
/// Application and gate failures are returned as auditable attempt records.
///
/// # Errors
/// Returns an error only for worktree lifecycle failures or original-tree drift.
pub async fn run_patch_attempt<E: PatchGateExecutor>(
    repository: &Path,
    id: PatchAttemptId,
    patch: &[u8],
    decision: PatchDecision,
    ladder: &VerificationLadder<E>,
    cancellation: &CancellationToken,
) -> Result<PatchAttemptRecord, PatchLoopError> {
    if decision != PatchDecision::Approved {
        return Err(PatchLoopError::PatchApprovalRequired);
    }
    let patch_sha256 = format!("{:x}", Sha256::digest(patch));
    let worktree = DisposableWorktree::create(repository)?;
    let record = if cancellation.is_cancelled() {
        empty_record(id, patch_sha256, PatchAttemptStatus::Cancelled)
    } else if let Err(error) = worktree.apply_patch(patch) {
        application_failure(id, patch_sha256, &error)
    } else {
        let patched_tree_sha256 = fingerprint_repository(worktree.path())?.status_sha256;
        let result = ladder.run(worktree.path(), cancellation).await;
        let status = if result.cancelled {
            PatchAttemptStatus::Cancelled
        } else if result.verification.all_required_gates_pass() {
            PatchAttemptStatus::Verified
        } else {
            PatchAttemptStatus::Failed
        };
        PatchAttemptRecord::new(
            id,
            patch_sha256,
            status,
            result.evidence,
            result.verification,
        )
        .with_worktree_sha256(patched_tree_sha256)
    };
    worktree.cleanup()?;
    Ok(record)
}

fn application_failure(
    id: PatchAttemptId,
    digest: String,
    error: &PatchLoopError,
) -> PatchAttemptRecord {
    let message = error.to_string();
    let evidence = PatchGateEvidence {
        schema_version: SCHEMA_VERSION,
        gate: PatchGate::BuildBaseline,
        variant_index: None,
        outcome: GateOutcome::Failed,
        command: vec!["git".into(), "apply".into()],
        exit_code: Some(1),
        stdout_sha256: format!("{:x}", Sha256::digest([])),
        stderr_sha256: format!("{:x}", Sha256::digest(message.as_bytes())),
        summary: message,
    };
    PatchAttemptRecord::new(
        id,
        digest,
        PatchAttemptStatus::Failed,
        vec![evidence],
        failed_verification(),
    )
}

fn empty_record(
    id: PatchAttemptId,
    digest: String,
    status: PatchAttemptStatus,
) -> PatchAttemptRecord {
    PatchAttemptRecord::new(id, digest, status, Vec::new(), failed_verification())
}

fn failed_verification() -> PatchVerification {
    PatchVerification {
        schema_version: SCHEMA_VERSION,
        build: GateOutcome::Failed,
        original_proof_stopped: GateOutcome::Failed,
        negative_control: GateOutcome::Failed,
        regression_suite: GateOutcome::Failed,
        static_rescan: GateOutcome::Failed,
        variant_search: GateOutcome::Failed,
        replay: GateOutcome::Failed,
    }
}

/// Hashes the complete porcelain status of a repository for drift detection.
///
/// # Errors
/// Returns an error if Git cannot inspect the repository.
pub fn fingerprint_repository(repository: &Path) -> Result<RepositoryFingerprint, PatchLoopError> {
    let output = git_output(
        repository,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?;
    require_success(output).map(|bytes| RepositoryFingerprint {
        status_sha256: format!("{:x}", Sha256::digest(bytes)),
    })
}

fn git_success(repository: &Path, arguments: &[&str]) -> Result<(), PatchLoopError> {
    require_success(git_output(repository, arguments)?).map(|_| ())
}

fn git_output(repository: &Path, arguments: &[&str]) -> Result<Output, PatchLoopError> {
    Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .output()
        .map_err(PatchLoopError::Io)
}

fn require_success(output: Output) -> Result<Vec<u8>, PatchLoopError> {
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(PatchLoopError::Git {
            code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

fn path_text(path: &Path) -> Result<&str, PatchLoopError> {
    path.to_str().ok_or(PatchLoopError::NonUnicodePath)
}

#[derive(Debug, Error)]
pub enum PatchLoopError {
    #[error("patch application requires an explicit approval")]
    PatchApprovalRequired,
    #[error("patch is {actual} bytes, exceeding the {limit}-byte limit")]
    PatchTooLarge { actual: usize, limit: usize },
    #[error("patch is not valid UTF-8")]
    NonUtf8Patch,
    #[error("binary patches are not accepted")]
    BinaryPatch,
    #[error("patch has a malformed diff header")]
    MalformedPatchHeader,
    #[error("patch has no diff header")]
    MissingPatchHeader,
    #[error("patch cannot create, delete, or rename files")]
    FileCreationOrDeletion,
    #[error("patch path is unsafe: {0}")]
    UnsafePatchPath(String),
    #[error("patch changes a path outside the admitted repository: {0}")]
    PatchPathNotAdmitted(PathBuf),
    #[error("patch does not change the confirmed finding path: {0}")]
    UnrelatedPatch(PathBuf),
    #[error("patch repository is not a directory")]
    NotDirectory,
    #[error("patch repository has no parent directory")]
    MissingParent,
    #[error("patch path is not Unicode")]
    NonUnicodePath,
    #[error("Git failed with {code:?}: {stderr}")]
    Git { code: Option<i32>, stderr: String },
    #[error("original working tree changed during patch verification")]
    OriginalTreeChanged,
    #[error("patch worktree I/O failed: {0}")]
    Io(#[from] std::io::Error),
}
