use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use edsa_cli::resume;
use edsa_cli::run_report;
use edsa_cli::scan::{self, ScanArguments};
use edsa_core::{RunApprovals, RunBudget, RunStatus, Verdict};
use edsa_reporting::replay_finding;
use edsa_sandbox::{DockerRunner, SandboxPolicy};
use tokio_util::sync::CancellationToken;

#[tokio::test]
#[ignore = "requires configured hosted-model credentials and Docker Desktop; incurs API cost"]
#[allow(clippy::too_many_lines)]
async fn interrupted_live_scan_resumes_once_and_replays_every_language() {
    let temporary = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let repository = temporary.path().join("repository");
    fs::create_dir(&repository).unwrap();
    write_fixture(&repository);
    initialize_git(&repository);
    let output = temporary.path().join("run");
    let cancellation = CancellationToken::new();
    let watcher_cancellation = cancellation.clone();
    let watcher_output = output.clone();
    let watcher = std::thread::spawn(move || {
        wait_for_checkpoint(
            &watcher_output,
            "role:hypothesis_planner",
            Duration::from_secs(180),
        );
        watcher_cancellation.cancel();
    });
    let interrupted = scan::execute(
        ScanArguments {
            repository: repository.clone(),
            output: output.clone(),
            budget: RunBudget {
                maximum_model_tokens: 30_000,
                maximum_cost_microusd: 2_000_000,
                maximum_turns: 12,
                maximum_experiments: 3,
                maximum_wall_time_seconds: 1_200,
            },
            approvals: RunApprovals::default(),
            optional_tools: BTreeSet::new(),
            admit_only: false,
            propose_patches: false,
            live: false,
        },
        cancellation,
    )
    .await;
    watcher.join().unwrap();
    assert!(interrupted.is_err());
    let paused = edsa_evidence::RunStore::open(&output).unwrap();
    assert_eq!(paused.current_status().unwrap(), Some(RunStatus::Running));
    drop(paused);

    let outcome = resume::execute(&output, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(outcome.status, RunStatus::Completed);
    let ledger = fs::read_to_string(output.join("events.jsonl")).unwrap();
    assert_eq!(
        ledger.matches("\"checkpoint_key\":\"role:mapper\"").count(),
        1
    );
    assert_eq!(
        ledger
            .matches("\"checkpoint_key\":\"role:hypothesis_planner\"")
            .count(),
        1
    );

    let manifest = run_report::verify_run(&output).unwrap();
    let mut replayed_languages = HashSet::new();
    for finding in manifest
        .findings
        .iter()
        .filter(|finding| finding.verdict == Verdict::Confirmed)
    {
        let plan = manifest
            .replay_plans
            .iter()
            .find(|plan| plan.finding_id == finding.id)
            .unwrap();
        let mut policy = SandboxPolicy::default();
        policy
            .allowed_environment
            .extend(plan.environment.keys().cloned());
        policy
            .allowed_environment
            .insert("EDSA_NEGATIVE_CONTROL".into());
        plan.sandbox_policy.apply_to(&mut policy);
        let evidence = replay_finding(
            &run_report::bundle_path(&output),
            &repository,
            &finding.id,
            Arc::new(DockerRunner::new(policy)),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(
            evidence.oracle_passed && evidence.negative_control_passed,
            "replay failed for {} at {}: {evidence:#?}",
            finding.id,
            finding.relative_path
        );
        replayed_languages.insert(language(&finding.relative_path));
    }
    assert_eq!(
        replayed_languages,
        HashSet::from(["python", "typescript", "go"])
    );
}

fn wait_for_checkpoint(output: &Path, key: &str, timeout: Duration) {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if fs::read_to_string(output.join("events.jsonl"))
            .is_ok_and(|events| events.contains(&format!("\"checkpoint_key\":\"{key}\"")))
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("checkpoint {key:?} was not recorded before the timeout");
}

fn language(path: &str) -> &'static str {
    match Path::new(path).extension().and_then(|value| value.to_str()) {
        Some("py" | "pyi") => "python",
        Some("js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx") => "typescript",
        Some("go") => "go",
        _ => "unknown",
    }
}

fn write_fixture(repository: &Path) {
    write(repository, "safe.txt", "safe\n");
    write(
        repository,
        "app.py",
        "from pathlib import Path\n\ndef read_file(user_path):\n    return Path(user_path).read_text()\n",
    );
    write(
        repository,
        "app.mjs",
        "import {readFile} from 'node:fs/promises';\nexport async function readUserFile(path) { return readFile(path, 'utf8'); }\n",
    );
    write(
        repository,
        "package.json",
        "{\"name\":\"fixture\",\"private\":true,\"type\":\"module\"}\n",
    );
    write(
        repository,
        "package-lock.json",
        "{\"name\":\"fixture\",\"lockfileVersion\":3,\"packages\":{}}\n",
    );
    write(
        repository,
        "go.mod",
        "module example.invalid/fixture\n\ngo 1.24\n",
    );
    write(
        repository,
        "fixture.go",
        "package fixture\n\nimport \"os\"\nfunc ReadUserFile(path string) ([]byte,error) { return os.ReadFile(path) }\n",
    );
    write(
        repository,
        "fixture_test.go",
        "package fixture\nimport (\"bytes\";\"fmt\";\"os\";\"testing\")\nfunc TestFilesystemBoundary(t *testing.T) { control:=os.Getenv(\"EDSA_NEGATIVE_CONTROL\")==\"1\"; p:=\"../../../../../../etc/passwd\"; if control { p=\"safe.txt\" }; b,e:=ReadUserFile(p); if e!=nil { fmt.Println(\"EDSA_NOT_REPRODUCED\"); return }; v:=bytes.Contains(b,[]byte(\"root:\")); if control&&!v {fmt.Println(\"EDSA_CONTROL_CLEAN\")} else if v {fmt.Println(\"EDSA_VULNERABLE\")} }\n",
    );
}

fn write(root: &Path, path: &str, body: &str) {
    fs::write(root.join(path), body).unwrap();
}

fn initialize_git(repository: &Path) {
    for arguments in [
        vec!["init"],
        vec!["config", "user.email", "tests@example.invalid"],
        vec!["config", "user.name", "EDSA Tests"],
        vec!["add", "."],
        vec!["commit", "-m", "polyglot fixture"],
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(repository)
                .args(arguments)
                .status()
                .unwrap()
                .success()
        );
    }
}
