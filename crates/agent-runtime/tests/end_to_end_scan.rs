use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    process::Command,
};

use edsa_agent_runtime::{SelectedAdapter, execute_hypothesis};
use edsa_core::{
    DirtyTreeDecision, Hypothesis, HypothesisId, ProviderMetadata, RepositoryPolicy, RunApprovals,
    RunBudget, RunConfiguration, SCHEMA_VERSION, Signal, SignalId, SignalSource, Verdict,
    ingest_repository,
};
use edsa_evidence::RunStore;
use edsa_reporting::verify_bundle;
use tokio_util::sync::CancellationToken;

fn write(root: &std::path::Path, path: &str, body: &str) {
    let target = root.join(path);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(target, body).unwrap();
}

fn git(root: &std::path::Path, args: &[&str]) {
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success()
    );
}

fn signal(id: &str, rule: &str, path: &str, line: u32) -> Signal {
    Signal {
        schema_version: SCHEMA_VERSION,
        id: SignalId::new(id),
        source: SignalSource::BuiltInRule,
        rule: rule.into(),
        relative_path: path.into(),
        start_line: line,
        message: rule.into(),
        metadata: BTreeMap::new(),
    }
}

fn hypothesis(id: &str, title: &str, weakness: &str, signal: &Signal) -> Hypothesis {
    Hypothesis {
        schema_version: SCHEMA_VERSION,
        id: HypothesisId::new(id),
        title: title.into(),
        claim: title.into(),
        weakness: weakness.into(),
        signal_ids: vec![signal.id.clone()],
    }
}

#[tokio::test]
#[ignore = "requires Docker Desktop and downloads the Python, Node, and Go runtime images"]
#[allow(clippy::too_many_lines)]
async fn real_polyglot_scan_selects_three_adapters_and_verifies_bundles() {
    // Docker Desktop on Windows can stall when bind-mounting the system Temp
    // directory. Keep the disposable fixture beside this crate so it uses the
    // same shared project filesystem as a normal scan.
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
    git(&repository, &["commit", "-m", "fixture"]);
    let inventory = ingest_repository(&repository, &RepositoryPolicy::default()).unwrap();
    let config = RunConfiguration::new(
        inventory.snapshot.clone(),
        ProviderMetadata {
            provider: "integration".into(),
            model: "none".into(),
        },
        RunBudget {
            maximum_model_tokens: 1,
            maximum_cost_microusd: 1,
            maximum_turns: 1,
            maximum_experiments: 3,
            maximum_wall_time_seconds: 300,
        },
        RunApprovals::default(),
        DirtyTreeDecision::Clean,
        inventory.detection.languages.clone(),
        Vec::new(),
    );
    let mut store = RunStore::create(temporary.path().join("run"), &config).unwrap();
    store
        .append_event(edsa_core::RunStatus::Ready, "integration")
        .unwrap();
    let cases = [
        (
            signal("py-signal", "path-traversal", "app.py", 4),
            "py-case",
            "Python path traversal",
            "CWE-22",
            SelectedAdapter::Python,
        ),
        (
            signal("js-signal", "path-traversal", "app.mjs", 2),
            "js-case",
            "JavaScript path traversal",
            "CWE-22",
            SelectedAdapter::TypeScript,
        ),
        (
            signal("go-signal", "filesystem-boundary", "fixture.go", 4),
            "go-case",
            "Go filesystem boundary",
            "CWE-22",
            SelectedAdapter::Go,
        ),
    ];
    let mut selected = BTreeSet::new();
    for (signal, id, title, weakness, adapter) in cases {
        let hypothesis = hypothesis(id, title, weakness, &signal);
        let result = execute_hypothesis(
            &repository,
            &inventory,
            &hypothesis,
            std::slice::from_ref(&signal),
            &store,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        eprintln!("Task 19 Docker result for {id}: {result:#?}");
        assert_eq!(result.adapter, adapter);
        assert_eq!(
            result.verdict,
            Verdict::Confirmed,
            "machine gates for {id}: {result:#?}"
        );
        selected.insert(result.adapter as u8);
        verify_bundle(&store.root().join("cases").join(id)).unwrap();
    }
    assert_eq!(selected.len(), 3);
}
