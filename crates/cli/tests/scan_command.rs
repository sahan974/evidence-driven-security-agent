use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

fn initialize_repository() -> (TempDir, PathBuf) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let repository = temporary.path().join("repository");
    fs::create_dir(&repository).expect("repository directory");
    fs::write(repository.join("app.py"), "print('accepted')\n").expect("source file");
    git(&repository, &["init"]);
    git(
        &repository,
        &["config", "user.email", "tests@example.invalid"],
    );
    git(&repository, &["config", "user.name", "EDSA Tests"]);
    git(&repository, &["add", "app.py"]);
    git(&repository, &["commit", "-m", "fixture"]);
    (temporary, repository)
}

fn git(repository: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .expect("git should start");
    assert!(status.success(), "git command failed: {arguments:?}");
}

fn scan(current_directory: &Path, repository: &Path, output: &Path, extra: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_edsa"));
    command
        .current_dir(current_directory)
        .arg("scan")
        .arg(repository)
        .arg("--output")
        .arg(output)
        .args([
            "--max-tokens",
            "1000",
            "--max-cost-microusd",
            "1000",
            "--max-turns",
            "5",
            "--max-experiments",
            "3",
            "--timeout-seconds",
            "60",
        ])
        .args(extra)
        .arg("--admit-only")
        .env("MODEL_PROVIDER", "openai-compatible")
        .env("MODEL_API_KEY", "contract-test-key")
        .env(
            "MODEL_API_URL",
            "https://example.invalid/v1/chat/completions",
        )
        .env("MODEL_NAME", "contract-test-model")
        .env_remove("OPENROUTER_API_KEY");
    command.output().expect("edsa should start")
}

#[test]
fn relative_repository_creates_a_durable_admitted_run() {
    let (temporary, repository) = initialize_repository();
    let output = temporary.path().join("evidence");
    let result = scan(
        temporary.path(),
        Path::new("repository"),
        Path::new("evidence"),
        &[],
    );
    assert!(
        result.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let response: Value = serde_json::from_slice(&result.stdout).expect("scan response JSON");
    assert_eq!(response["status"], "ready");
    assert!(
        response["run_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("run-"))
    );
    assert!(output.join("run.json").is_file());
    assert!(output.join("ledger.sqlite3").is_file());
    assert!(output.join("events.jsonl").is_file());
    assert!(output.join("artifacts/sha256").is_dir());

    let metadata = fs::read_to_string(output.join("run.json")).expect("run metadata");
    assert!(metadata.contains("contract-test-model"));
    assert!(metadata.contains("python"));
    assert!(!metadata.contains("contract-test-key"));
    assert!(repository.join(".git").is_dir());
}

#[test]
fn absolute_dirty_repository_requires_explicit_approval() {
    let (temporary, repository) = initialize_repository();
    fs::write(repository.join("app.py"), "print('changed')\n").expect("dirty source");
    let rejected = scan(
        temporary.path(),
        &repository,
        &temporary.path().join("rejected"),
        &[],
    );
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("--allow-dirty"));

    let accepted = scan(
        temporary.path(),
        &repository,
        &temporary.path().join("accepted"),
        &["--allow-dirty"],
    );
    assert!(
        accepted.status.success(),
        "approved scan failed: {}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let metadata = fs::read_to_string(temporary.path().join("accepted/run.json"))
        .expect("approved run metadata");
    assert!(metadata.contains("explicitly_allowed"));
}

#[test]
fn invalid_path_missing_key_zero_budget_and_collision_fail() {
    let (temporary, repository) = initialize_repository();

    let invalid_path = scan(
        temporary.path(),
        Path::new("missing"),
        Path::new("invalid-path"),
        &[],
    );
    assert!(!invalid_path.status.success());
    assert!(!temporary.path().join("invalid-path").exists());

    let missing_key = Command::new(env!("CARGO_BIN_EXE_edsa"))
        .current_dir(temporary.path())
        .args([
            "scan",
            "repository",
            "--output",
            "missing-key",
            "--max-tokens",
            "1",
            "--max-cost-microusd",
            "1",
            "--max-turns",
            "1",
            "--max-experiments",
            "1",
            "--timeout-seconds",
            "1",
        ])
        .env("MODEL_PROVIDER", "openai-compatible")
        .env("MODEL_API_URL", "https://example.invalid")
        .env("MODEL_NAME", "contract-test-model")
        .env_remove("MODEL_API_KEY")
        .output()
        .expect("edsa should start");
    assert!(!missing_key.status.success());
    assert!(String::from_utf8_lossy(&missing_key.stderr).contains("MODEL_API_KEY"));
    assert!(!temporary.path().join("missing-key").exists());

    let zero_budget = Command::new(env!("CARGO_BIN_EXE_edsa"))
        .current_dir(temporary.path())
        .args([
            "scan",
            "repository",
            "--output",
            "zero",
            "--max-tokens",
            "0",
            "--max-cost-microusd",
            "1",
            "--max-turns",
            "1",
            "--max-experiments",
            "1",
            "--timeout-seconds",
            "1",
        ])
        .output()
        .expect("edsa should start");
    assert!(!zero_budget.status.success());
    assert!(String::from_utf8_lossy(&zero_budget.stderr).contains("greater than zero"));

    fs::create_dir(temporary.path().join("collision")).expect("collision directory");
    let collision = scan(temporary.path(), &repository, Path::new("collision"), &[]);
    assert!(!collision.status.success());
    assert!(String::from_utf8_lossy(&collision.stderr).contains("already exists"));

    let unsafe_output = scan(
        temporary.path(),
        &repository,
        &repository.join("generated-evidence"),
        &[],
    );
    assert!(!unsafe_output.status.success());
    assert!(String::from_utf8_lossy(&unsafe_output.stderr).contains("outside"));

    let unsupported = temporary.path().join("unsupported");
    fs::create_dir(&unsupported).expect("unsupported repository");
    fs::write(unsupported.join("README.txt"), "no supported source\n").expect("readme");
    git(&unsupported, &["init"]);
    git(
        &unsupported,
        &["config", "user.email", "tests@example.invalid"],
    );
    git(&unsupported, &["config", "user.name", "EDSA Tests"]);
    git(&unsupported, &["add", "README.txt"]);
    git(&unsupported, &["commit", "-m", "fixture"]);
    let unsupported_result = scan(
        temporary.path(),
        &unsupported,
        &temporary.path().join("unsupported-output"),
        &[],
    );
    assert!(!unsupported_result.status.success());
    assert!(String::from_utf8_lossy(&unsupported_result.stderr).contains("supported Python"));
}
