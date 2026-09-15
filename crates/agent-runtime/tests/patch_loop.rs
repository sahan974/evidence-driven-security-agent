use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use edsa_agent_runtime::{
    GateExecution, PatchDecision, PatchGateExecutor, PatchValidationPolicy, VerificationLadder,
    VerificationPolicy, run_patch_attempt, validate_unified_diff,
};
use edsa_core::{GateOutcome, PatchAttemptId, PatchAttemptStatus, PatchGate};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

const PATCH: &[u8] = b"diff --git a/app.txt b/app.txt\n--- a/app.txt\n+++ b/app.txt\n@@ -1 +1 @@\n-vulnerable\n+patched\n";
const STANDARD_UNIFIED_PATCH: &[u8] =
    b"--- a/app.txt\n+++ b/app.txt\n@@ -1 +1 @@\n-vulnerable\n+patched\n";
const INACCURATE_COUNTS_PATCH: &[u8] =
    b"--- a/app.txt\n+++ b/app.txt\n@@ -1,99 +1,42 @@\n-vulnerable\n+patched\n";

#[derive(Clone, Copy, Debug)]
enum Mode {
    Pass,
    FailRegression,
    FailVariant,
    Cancel,
}

#[derive(Debug)]
struct FixtureGates {
    original: PathBuf,
    mode: Mode,
    observed: Arc<Mutex<Vec<PathBuf>>>,
}

#[async_trait]
impl PatchGateExecutor for FixtureGates {
    async fn execute(
        &self,
        worktree: &Path,
        gate: PatchGate,
        variant_index: Option<u32>,
        cancellation: CancellationToken,
    ) -> GateExecution {
        assert_ne!(worktree, self.original);
        assert_eq!(
            std::fs::read_to_string(worktree.join("app.txt"))
                .unwrap()
                .trim_end(),
            "patched"
        );
        self.observed.lock().unwrap().push(worktree.to_path_buf());
        if matches!(self.mode, Mode::Cancel) && gate == PatchGate::OriginalProofStopped {
            cancellation.cancel();
        }
        let failed = matches!(self.mode, Mode::FailRegression) && gate == PatchGate::Regression
            || matches!(self.mode, Mode::FailVariant)
                && gate == PatchGate::VariantSearch
                && variant_index == Some(1);
        GateExecution {
            command: vec!["fixture-gate".into(), format!("{gate:?}")],
            exit_code: Some(i32::from(failed)),
            stdout: format!("{gate:?}:{variant_index:?}").into_bytes(),
            stderr: if failed {
                b"machine failure".to_vec()
            } else {
                Vec::new()
            },
        }
    }
}

#[tokio::test]
async fn patch_loop_success_keeps_original_tree_clean_and_verifies_all_gates() {
    let repository = repository();
    let before = original_state(repository.path());
    let observed = Arc::new(Mutex::new(Vec::new()));
    let ladder = ladder(repository.path(), Mode::Pass, observed.clone());
    let record = run_patch_attempt(
        repository.path(),
        PatchAttemptId::new("patch-success"),
        PATCH,
        PatchDecision::Approved,
        &ladder,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(record.status, PatchAttemptStatus::Verified);
    assert!(record.verification.all_required_gates_pass());
    assert_eq!(
        record
            .gates
            .iter()
            .filter(|gate| gate.gate == PatchGate::VariantSearch)
            .count(),
        3
    );
    assert_original_unchanged(repository.path(), &before);
    assert!(observed.lock().unwrap().iter().all(|path| !path.exists()));
}

#[tokio::test]
async fn patch_loop_recounts_generated_hunk_lengths_before_application() {
    let repository = repository();
    let ladder = ladder(
        repository.path(),
        Mode::Pass,
        Arc::new(Mutex::new(Vec::new())),
    );
    let record = run_patch_attempt(
        repository.path(),
        PatchAttemptId::new("patch-recount"),
        INACCURATE_COUNTS_PATCH,
        PatchDecision::Approved,
        &ladder,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(record.status, PatchAttemptStatus::Verified);
}

#[tokio::test]
async fn patch_loop_preserves_patch_context_when_autocrlf_is_enabled() {
    let repository = repository();
    git(repository.path(), &["config", "core.autocrlf", "true"]);
    let ladder = ladder(
        repository.path(),
        Mode::Pass,
        Arc::new(Mutex::new(Vec::new())),
    );
    let record = run_patch_attempt(
        repository.path(),
        PatchAttemptId::new("patch-autocrlf"),
        PATCH,
        PatchDecision::Approved,
        &ladder,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(record.status, PatchAttemptStatus::Verified);
}

#[tokio::test]
async fn patch_loop_failed_regression_is_auditable_and_cleans_up() {
    let repository = repository();
    let before = original_state(repository.path());
    let observed = Arc::new(Mutex::new(Vec::new()));
    let ladder = ladder(repository.path(), Mode::FailRegression, observed.clone());
    let record = run_patch_attempt(
        repository.path(),
        PatchAttemptId::new("patch-regression"),
        PATCH,
        PatchDecision::Approved,
        &ladder,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(record.status, PatchAttemptStatus::Failed);
    assert_eq!(record.gates.last().unwrap().gate, PatchGate::Regression);
    assert_eq!(record.gates.last().unwrap().outcome, GateOutcome::Failed);
    assert!(!record.gates.last().unwrap().stderr_sha256.is_empty());
    assert_original_unchanged(repository.path(), &before);
    assert!(observed.lock().unwrap().iter().all(|path| !path.exists()));
}

#[tokio::test]
async fn patch_loop_incomplete_patch_is_rejected_by_bounded_variant_search() {
    let repository = repository();
    let before = original_state(repository.path());
    let ladder = ladder(
        repository.path(),
        Mode::FailVariant,
        Arc::new(Mutex::new(Vec::new())),
    );
    let record = run_patch_attempt(
        repository.path(),
        PatchAttemptId::new("patch-incomplete"),
        PATCH,
        PatchDecision::Approved,
        &ladder,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(record.status, PatchAttemptStatus::Failed);
    assert_eq!(record.verification.variant_search, GateOutcome::Failed);
    let variants = record
        .gates
        .iter()
        .filter(|gate| gate.gate == PatchGate::VariantSearch)
        .collect::<Vec<_>>();
    assert_eq!(variants.len(), 2);
    assert_eq!(variants[1].outcome, GateOutcome::Failed);
    assert_original_unchanged(repository.path(), &before);
}

#[tokio::test]
async fn patch_loop_cancellation_is_recorded_and_removes_worktree() {
    let repository = repository();
    let before = original_state(repository.path());
    let observed = Arc::new(Mutex::new(Vec::new()));
    let ladder = ladder(repository.path(), Mode::Cancel, observed.clone());
    let record = run_patch_attempt(
        repository.path(),
        PatchAttemptId::new("patch-cancel"),
        PATCH,
        PatchDecision::Approved,
        &ladder,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(record.status, PatchAttemptStatus::Cancelled);
    assert!(!record.verification.all_required_gates_pass());
    assert_original_unchanged(repository.path(), &before);
    assert!(observed.lock().unwrap().iter().all(|path| !path.exists()));
}

#[tokio::test]
async fn patch_loop_invalid_diff_is_preserved_as_failed_machine_evidence() {
    let repository = repository();
    let before = original_state(repository.path());
    let ladder = ladder(
        repository.path(),
        Mode::Pass,
        Arc::new(Mutex::new(Vec::new())),
    );
    let record = run_patch_attempt(
        repository.path(),
        PatchAttemptId::new("patch-invalid"),
        b"not a patch",
        PatchDecision::Approved,
        &ladder,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(record.status, PatchAttemptStatus::Failed);
    assert_eq!(record.gates.len(), 1);
    assert_eq!(record.gates[0].gate, PatchGate::BuildBaseline);
    assert_original_unchanged(repository.path(), &before);
}

#[tokio::test]
async fn security_patch_application_requires_explicit_approval() {
    let repository = repository();
    let ladder = ladder(
        repository.path(),
        Mode::Pass,
        Arc::new(Mutex::new(Vec::new())),
    );
    let error = run_patch_attempt(
        repository.path(),
        PatchAttemptId::new("patch-denied"),
        PATCH,
        PatchDecision::Denied,
        &ladder,
        &CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("explicit approval"));
}

#[test]
fn untrusted_diff_validation_rejects_scope_and_path_bypasses() {
    let policy = PatchValidationPolicy {
        maximum_bytes: 1024,
        allowed_paths: std::collections::BTreeSet::from([PathBuf::from("app.txt")]),
        required_path: PathBuf::from("app.txt"),
    };
    validate_unified_diff(PATCH, &policy).expect("in-scope patch");
    validate_unified_diff(STANDARD_UNIFIED_PATCH, &policy)
        .expect("standard unified patch without Git preamble");
    for rejected in [
        b"diff --git a/../secret b/../secret\n--- a/../secret\n+++ b/../secret\n".as_slice(),
        b"diff --git a/other.txt b/other.txt\n--- a/other.txt\n+++ b/other.txt\n".as_slice(),
        b"not a unified diff".as_slice(),
        b"diff --git a/app.txt b/app.txt\nGIT binary patch\n".as_slice(),
        b"--- a/app.txt\n+++ b/app.txt\n@@\n-vulnerable\n+patched\n".as_slice(),
    ] {
        assert!(validate_unified_diff(rejected, &policy).is_err());
    }
}

#[test]
fn untrusted_diff_validation_rejects_oversized_input() {
    let policy = PatchValidationPolicy {
        maximum_bytes: 8,
        allowed_paths: std::collections::BTreeSet::from([PathBuf::from("app.txt")]),
        required_path: PathBuf::from("app.txt"),
    };
    assert!(validate_unified_diff(PATCH, &policy).is_err());
}

fn ladder(
    repository: &Path,
    mode: Mode,
    observed: Arc<Mutex<Vec<PathBuf>>>,
) -> VerificationLadder<FixtureGates> {
    VerificationLadder::new(
        FixtureGates {
            original: repository.canonicalize().unwrap(),
            mode,
            observed,
        },
        VerificationPolicy {
            maximum_variant_cases: 3,
        },
    )
    .unwrap()
}

fn repository() -> TempDir {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("app.txt"), "vulnerable\n").unwrap();
    git(directory.path(), &["init", "--quiet"]);
    git(
        directory.path(),
        &["config", "user.email", "fixture@example.invalid"],
    );
    git(directory.path(), &["config", "user.name", "Fixture"]);
    git(directory.path(), &["add", "app.txt"]);
    git(directory.path(), &["commit", "--quiet", "-m", "fixture"]);
    directory
}

fn original_state(repository: &Path) -> (String, Vec<u8>) {
    (
        std::fs::read_to_string(repository.join("app.txt")).unwrap(),
        git_bytes(
            repository,
            &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        ),
    )
}

fn assert_original_unchanged(repository: &Path, before: &(String, Vec<u8>)) {
    assert_eq!(
        std::fs::read_to_string(repository.join("app.txt")).unwrap(),
        before.0
    );
    assert_eq!(
        git_bytes(
            repository,
            &["status", "--porcelain=v1", "-z", "--untracked-files=all"]
        ),
        before.1
    );
    assert_eq!(
        String::from_utf8(git_bytes(repository, &["worktree", "list", "--porcelain"]))
            .unwrap()
            .matches("worktree ")
            .count(),
        1
    );
}

fn git(root: &Path, arguments: &[&str]) {
    assert!(
        Command::new("git")
            .args(arguments)
            .current_dir(root)
            .status()
            .unwrap()
            .success()
    );
}

fn git_bytes(root: &Path, arguments: &[&str]) -> Vec<u8> {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
