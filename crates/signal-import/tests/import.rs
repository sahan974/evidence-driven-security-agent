use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use async_trait::async_trait;
use edsa_core::{
    ConfirmationPolicy, EvidenceAssessment, RepositoryPolicy, SignalSource, Verdict,
    ingest_repository,
};
use edsa_sandbox::{
    CommandExecutor, CommandOutput, CommandSpec, ExecutionError, ProcessCommandExecutor,
};
use edsa_signal_import::{
    SemgrepError, SemgrepOptions, collect_builtin_signals, correlate_signals, import_sarif,
    run_semgrep,
};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

const VALID: &[u8] = include_bytes!("fixtures/valid.sarif.json");
const MALFORMED: &[u8] = include_bytes!("fixtures/malformed.sarif.json");

#[test]
fn valid_sarif_retains_tool_rule_location_flow_and_artifact() {
    let signals = import_sarif(VALID, "artifacts/fixture.sarif").unwrap();
    assert_eq!(signals.len(), 1);
    let signal = &signals[0];
    assert_eq!(signal.source, SignalSource::ExternalAnalyzer);
    assert_eq!(signal.rule, "security/command-injection");
    assert_eq!(signal.relative_path, "src/main.py");
    assert_eq!(signal.start_line, 7);
    assert_eq!(signal.metadata["provenance.tool"], "FixtureScan");
    assert_eq!(signal.metadata["provenance.tool_version"], "1.2.3");
    assert_eq!(
        signal.metadata["provenance.artifact"],
        "artifacts/fixture.sarif"
    );
    assert!(signal.metadata["sarif.code_flows"].contains("threadFlows"));
}

#[test]
fn malformed_and_wrong_version_sarif_are_rejected() {
    assert!(import_sarif(MALFORMED, "broken").is_err());
    assert!(import_sarif(br#"{"version":"2.0.0","runs":[]}"#, "old").is_err());
}

#[test]
fn duplicate_external_signals_are_correlated_without_losing_provenance() {
    let mut first = import_sarif(VALID, "first.sarif").unwrap();
    let mut second = import_sarif(VALID, "second.sarif").unwrap();
    first.append(&mut second);
    let groups = correlate_signals(&first);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].signal_ids.len(), 2);
    assert_eq!(first[0].metadata["provenance.artifact"], "first.sarif");
    assert_eq!(first[1].metadata["provenance.artifact"], "second.sarif");
}

#[test]
fn external_alert_is_not_confirmation_evidence() {
    let signal = import_sarif(VALID, "fixture.sarif").unwrap().remove(0);
    assert_eq!(signal.source, SignalSource::ExternalAnalyzer);
    let assessment = EvidenceAssessment {
        schema_version: edsa_core::SCHEMA_VERSION,
        baseline_passed: false,
        oracle_passed: false,
        negative_control_passed: false,
        reproduced_runs: 0,
        evidence: Vec::new(),
    };
    assert_eq!(
        ConfirmationPolicy::default().verdict(&assessment),
        Verdict::Inconclusive
    );
}

#[test]
fn builtins_work_without_an_external_analyzer() {
    let repository = fixture_repository();
    let inventory = ingest_repository(repository.path(), &RepositoryPolicy::default()).unwrap();
    let signals = collect_builtin_signals(repository.path(), &inventory).unwrap();
    assert!(
        signals
            .iter()
            .any(|signal| signal.rule == "repository-manifest")
    );
    assert!(signals.iter().any(|signal| signal.rule == "entry-point"));
    assert!(signals.iter().any(|signal| signal.rule == "test-file"));
    assert!(
        signals
            .iter()
            .any(|signal| signal.rule == "dangerous-command-execution")
    );
    assert!(
        signals
            .iter()
            .all(|signal| signal.source == SignalSource::BuiltInRule)
    );
}

#[tokio::test]
async fn missing_semgrep_is_an_optional_capability_limitation() {
    let options = SemgrepOptions {
        executable: "edsa-definitely-missing-semgrep-binary".into(),
        ..SemgrepOptions::default()
    };
    let result = run_semgrep(
        Arc::new(ProcessCommandExecutor),
        Path::new("."),
        &options,
        CancellationToken::new(),
    )
    .await;
    assert!(matches!(result, Err(SemgrepError::Unavailable(_))));
}

#[derive(Debug)]
struct SarifExecutor;

#[async_trait]
impl CommandExecutor for SarifExecutor {
    async fn execute(&self, specification: CommandSpec) -> Result<CommandOutput, ExecutionError> {
        assert_eq!(specification.arguments[0], "scan");
        Ok(CommandOutput {
            exit_code: Some(0),
            stdout: VALID.to_vec(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        })
    }
}

#[tokio::test]
async fn semgrep_sarif_uses_the_same_normalization_path() {
    let signals = run_semgrep(
        Arc::new(SarifExecutor),
        Path::new("."),
        &SemgrepOptions::default(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(signals[0].metadata["provenance.artifact"], "semgrep:stdout");
    assert_eq!(signals[0].source, SignalSource::ExternalAnalyzer);
}

fn fixture_repository() -> TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir_all(directory.path().join("src")).unwrap();
    fs::create_dir_all(directory.path().join("tests")).unwrap();
    fs::write(
        directory.path().join("Cargo.toml"),
        "[package]\nname='fixture'\nversion='0.1.0'\n",
    )
    .unwrap();
    fs::write(
        directory.path().join("src/main.rs"),
        "fn main() { std::process::Command::new(\"echo\"); }\n",
    )
    .unwrap();
    fs::write(
        directory.path().join("tests/check.rs"),
        "#[test] fn check() {}\n",
    )
    .unwrap();
    git(directory.path(), &["init", "--quiet"]);
    git(
        directory.path(),
        &["config", "user.email", "fixture@example.invalid"],
    );
    git(directory.path(), &["config", "user.name", "Fixture"]);
    git(directory.path(), &["add", "."]);
    git(directory.path(), &["commit", "--quiet", "-m", "fixture"]);
    directory
}

fn git(root: &Path, arguments: &[&str]) {
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
}
