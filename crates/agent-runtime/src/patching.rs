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
        let original = fingerprint(&repository)?;
        let parent = repository.parent().ok_or(PatchLoopError::MissingParent)?;
        let temporary = Builder::new().prefix("edsa-worktree-").tempdir_in(parent)?;
        let path = temporary.path().to_path_buf();
        temporary.close()?;
        git_success(
            &repository,
            &["worktree", "add", "--detach", path_text(&path)?, "HEAD"],
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
        git_success(&self.path, &["apply", "--check", patch_path])?;
        git_success(&self.path, &["apply", "--whitespace=nowarn", patch_path])
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
        let after = fingerprint(&self.repository)?;
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
    }
}

fn fingerprint(repository: &Path) -> Result<RepositoryFingerprint, PatchLoopError> {
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
