use std::collections::{BTreeSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use edsa_adapter_go::{
    GoExperimentKind, GoFailureKind, GoTarget, baseline_request, classify_failure,
    environment_plan, fuzz_request, generated_experiment, race_request, store_fuzz_artifacts,
};
use edsa_adapter_sdk::{ExperimentRunner, RecordedExecution, SandboxBackend, classify};
use edsa_core::{
    ConfirmationPolicy, LanguageDetection, RepositoryFile, RepositoryInventory, RepositorySnapshot,
    SCHEMA_VERSION, Verdict,
};
use edsa_evidence::ArtifactStore;
use edsa_sandbox::docker::SandboxError;
use edsa_sandbox::{SandboxOutput, SandboxRequest};
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
struct QueueSandbox {
    outputs: Mutex<VecDeque<SandboxOutput>>,
    requests: Mutex<Vec<SandboxRequest>>,
}

impl QueueSandbox {
    fn new(markers: &[(&str, &str, i32)]) -> Self {
        Self {
            outputs: Mutex::new(
                markers
                    .iter()
                    .map(|(stdout, stderr, code)| SandboxOutput {
                        container_name: "mock".into(),
                        exit_code: Some(*code),
                        stdout: stdout.as_bytes().to_vec(),
                        stderr: stderr.as_bytes().to_vec(),
                        stdout_truncated: false,
                        stderr_truncated: false,
                    })
                    .collect(),
            ),
            requests: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl SandboxBackend for QueueSandbox {
    async fn run(
        &self,
        request: SandboxRequest,
        _cancellation: CancellationToken,
    ) -> Result<SandboxOutput, SandboxError> {
        self.requests.lock().unwrap().push(request);
        Ok(self
            .outputs
            .lock()
            .unwrap()
            .pop_front()
            .expect("test output"))
    }
}

#[test]
fn module_plan_and_native_go_commands_are_locked_and_read_only() {
    let inventory = fixture_inventory();
    let mut with_sum = inventory.clone();
    with_sum.files.push(file("go.sum"));
    let plan = environment_plan(&with_sum).unwrap();
    assert!(plan.locked);
    assert_eq!(plan.preparation_command, ["go", "mod", "download"]);
    assert_eq!(
        baseline_request(fixture_root(), &plan).command[0..2],
        ["go", "test"]
    );
    let target = GoTarget {
        package: "./...".into(),
        test_name: "FuzzMalformed".into(),
    };
    assert!(
        fuzz_request(fixture_root(), &plan, &target, 5)
            .command
            .iter()
            .any(|value| value == "-fuzz=^FuzzMalformed$")
    );
    assert!(
        race_request(fixture_root(), &plan)
            .command
            .contains(&"-race".into())
    );
}

#[tokio::test]
async fn malformed_panic_can_be_confirmed_and_replayed() {
    let plan = environment_plan(&fixture_inventory()).unwrap();
    let backend = Arc::new(QueueSandbox::new(&[
        ("ok", "", 0),
        ("EDSA_VULNERABLE", "panic: index out of range", 0),
        ("EDSA_CONTROL_CLEAN", "", 0),
        ("EDSA_VULNERABLE", "panic: index out of range", 0),
        ("EDSA_CONTROL_CLEAN", "", 0),
    ]));
    let runner = ExperimentRunner::new(backend.clone());
    let (_, baseline) = runner
        .baseline(
            baseline_request(fixture_root(), &plan),
            &edsa_adapter_go::oracles::test_suite_passed(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let target = GoTarget {
        package: "./...".into(),
        test_name: "TestMalformedInputPanic".into(),
    };
    let (experiment, reproducer) = generated_experiment(
        fixture_root(),
        &plan,
        GoExperimentKind::MalformedInputPanic,
        &target,
    );
    let evidence = runner
        .execute(experiment, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        classify(&ConfirmationPolicy::default(), &evidence, baseline),
        Verdict::Confirmed
    );
    let replay = reproducer
        .replay(&runner, fixture_root(), CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(replay.oracle_passed, evidence.oracle_passed);
    assert!(
        backend
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.command[0] == "go")
    );
}

#[tokio::test]
async fn filesystem_boundary_can_be_rejected_with_a_clean_control() {
    let plan = environment_plan(&fixture_inventory()).unwrap();
    let backend = Arc::new(QueueSandbox::new(&[
        ("ok", "", 0),
        ("EDSA_NOT_REPRODUCED", "", 0),
        ("EDSA_CONTROL_CLEAN", "", 0),
    ]));
    let runner = ExperimentRunner::new(backend);
    let (_, baseline) = runner
        .baseline(
            baseline_request(fixture_root(), &plan),
            &edsa_adapter_go::oracles::test_suite_passed(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let target = GoTarget {
        package: "./...".into(),
        test_name: "TestFilesystemBoundary".into(),
    };
    let (experiment, _) = generated_experiment(
        fixture_root(),
        &plan,
        GoExperimentKind::FilesystemBoundary,
        &target,
    );
    let evidence = runner
        .execute(experiment, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        classify(&ConfirmationPolicy::default(), &evidence, baseline),
        Verdict::Rejected
    );
}

#[test]
fn fuzz_corpus_and_minimized_input_are_content_addressed() {
    let directory = tempfile::tempdir().unwrap();
    let store = ArtifactStore::open(directory.path()).unwrap();
    let bundle = store_fuzz_artifacts(
        &store,
        &[b"seed-one".to_vec(), b"seed-two".to_vec()],
        Some(b"x"),
    )
    .unwrap();
    assert_eq!(bundle.corpus.len(), 2);
    let minimized = bundle.minimized_failure.unwrap();
    assert_eq!(store.get(&minimized.sha256).unwrap(), b"x");
    assert_ne!(bundle.corpus[0].sha256, bundle.corpus[1].sha256);
}

#[test]
fn panic_and_race_have_distinct_stable_signatures() {
    let panic = execution(
        "",
        "panic: index out of range [3] with length 1\ngroutine 18",
        2,
    );
    let moved_panic = execution(
        "",
        "panic: index out of range [3] with length 1\ngroutine 92",
        2,
    );
    let race = execution("", "WARNING: DATA RACE\nRead at 0x00000123", 1);
    let panic_failure = classify_failure(&panic);
    assert_eq!(panic_failure.kind, GoFailureKind::Panic);
    assert_eq!(
        panic_failure.signature,
        classify_failure(&moved_panic).signature
    );
    let race_failure = classify_failure(&race);
    assert_eq!(race_failure.kind, GoFailureKind::Race);
    assert_ne!(panic_failure.signature, race_failure.signature);
}

fn execution(stdout: &str, stderr: &str, code: i32) -> RecordedExecution {
    RecordedExecution {
        command: vec!["go".into(), "test".into()],
        exit_code: Some(code),
        stdout: stdout.into(),
        stderr: stderr.into(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../benchmarks/go/fixture")
        .canonicalize()
        .unwrap()
}

fn fixture_inventory() -> RepositoryInventory {
    RepositoryInventory {
        schema_version: SCHEMA_VERSION,
        snapshot: RepositorySnapshot::new(".", "revision", "digest", false),
        files: vec![
            file("go.mod"),
            file("fixture.go"),
            file("fixture_test.go"),
            file("race_test.go"),
        ],
        exclusions: Vec::new(),
        detection: LanguageDetection {
            schema_version: SCHEMA_VERSION,
            languages: BTreeSet::default(),
            manifests: Vec::new(),
        },
    }
}

fn file(path: &str) -> RepositoryFile {
    RepositoryFile {
        schema_version: SCHEMA_VERSION,
        relative_path: path.into(),
        size_bytes: 1,
        sha256: "digest".into(),
    }
}
