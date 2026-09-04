use std::{collections::BTreeSet, fs, path::Path, process::Command};

use edsa_cli::scan::{self, ScanArguments};
use edsa_core::{RunApprovals, RunBudget, RunStatus};
use tokio_util::sync::CancellationToken;

fn write(root: &Path, path: &str, body: &str) {
    let target = root.join(path);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(target, body).unwrap();
}

fn git(root: &Path, arguments: &[&str]) {
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(arguments)
            .status()
            .unwrap()
            .success()
    );
}

#[tokio::test]
#[ignore = "requires configured hosted-model credentials and Docker Desktop; incurs API cost"]
async fn hosted_model_discovers_and_executes_polyglot_findings() {
    let temporary = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let repository = temporary.path().join("repository");
    fs::create_dir(&repository).unwrap();
    write(
        &repository,
        "app.py",
        "from pathlib import Path\n\ndef read_file(user_path):\n    return Path(user_path).read_text()\n",
    );
    write(&repository, "safe.txt", "safe\n");
    write(
        &repository,
        "app.mjs",
        "import {readFile} from 'node:fs/promises';\nexport async function readUserFile(path) { return readFile(path, 'utf8'); }\n",
    );
    write(
        &repository,
        "package.json",
        "{\"name\":\"fixture\",\"private\":true,\"type\":\"module\"}\n",
    );
    write(
        &repository,
        "package-lock.json",
        "{\"name\":\"fixture\",\"lockfileVersion\":3,\"packages\":{}}\n",
    );
    write(
        &repository,
        "go.mod",
        "module example.invalid/fixture\n\ngo 1.24\n",
    );
    write(
        &repository,
        "fixture.go",
        "package fixture\n\nimport \"os\"\nfunc ReadUserFile(path string) ([]byte,error) { return os.ReadFile(path) }\n",
    );
    write(
        &repository,
        "fixture_test.go",
        "package fixture\nimport (\"bytes\";\"fmt\";\"os\";\"testing\")\nfunc TestFilesystemBoundary(t *testing.T) { control:=os.Getenv(\"EDSA_NEGATIVE_CONTROL\")==\"1\"; p:=\"../../../../../../etc/passwd\"; if control { p=\"safe.txt\" }; b,e:=ReadUserFile(p); if e!=nil { fmt.Println(\"EDSA_NOT_REPRODUCED\"); return }; v:=bytes.Contains(b,[]byte(\"root:\")); if control&&!v {fmt.Println(\"EDSA_CONTROL_CLEAN\")} else if v {fmt.Println(\"EDSA_VULNERABLE\")} }\n",
    );
    git(&repository, &["init"]);
    git(
        &repository,
        &["config", "user.email", "tests@example.invalid"],
    );
    git(&repository, &["config", "user.name", "EDSA Tests"]);
    git(&repository, &["add", "."]);
    git(&repository, &["commit", "-m", "polyglot fixture"]);

    let output = temporary.path().join("run");
    let outcome = scan::execute(
        ScanArguments {
            repository,
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
        },
        CancellationToken::new(),
    )
    .await
    .unwrap();
    eprintln!("Task 19 live outcome: {outcome:#?}");
    assert_eq!(outcome.status, RunStatus::Completed);
    let events = fs::read_to_string(output.join("events.jsonl")).unwrap();
    eprintln!(
        "----- TASK 19 COMPLETE RUN LEDGER -----\n{events}----- END TASK 19 RUN LEDGER -----"
    );
    for adapter in ["python", "typescript", "go"] {
        assert!(
            events.contains(&format!("\"adapter\":\"{adapter}\"")),
            "missing adapter {adapter:?} in the printed Task 19 run ledger"
        );
    }
    assert!(events.contains("\"verdict\":\"confirmed\""));
}
