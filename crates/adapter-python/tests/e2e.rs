use std::collections::{BTreeSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use edsa_adapter_python::{
    DependencyManager, PythonFramework, PythonHypothesisKind, PythonTarget, baseline_request,
    environment_plan, generated_experiment, oracles,
};
use edsa_adapter_sdk::{ExperimentRunner, SandboxBackend, classify};
use edsa_core::{
    ConfirmationPolicy, LanguageDetection, RepositoryInventory, RepositorySnapshot, SCHEMA_VERSION,
    Verdict,
};
use edsa_sandbox::docker::SandboxError;
use edsa_sandbox::{SandboxOutput, SandboxRequest};
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
struct QueueSandbox {
    outputs: Mutex<VecDeque<SandboxOutput>>,
    requests: Mutex<Vec<SandboxRequest>>,
}

impl QueueSandbox {
    fn new(markers: &[(&str, i32)]) -> Self {
        Self {
            outputs: Mutex::new(
                markers
                    .iter()
                    .map(|(stdout, code)| SandboxOutput {
                        container_name: "mock".into(),
                        exit_code: Some(*code),
                        stdout: stdout.as_bytes().to_vec(),
                        stderr: Vec::new(),
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

#[tokio::test]
async fn confirmed_path_traversal_replays_without_a_model() {
    let root = fixture_root();
    let backend = Arc::new(QueueSandbox::new(&[
        ("1 passed", 0),
        ("EDSA_VULNERABLE", 0),
        ("EDSA_CONTROL_CLEAN", 0),
        ("EDSA_VULNERABLE", 0),
        ("EDSA_CONTROL_CLEAN", 0),
    ]));
    let runner = ExperimentRunner::new(backend.clone());
    let (_, baseline_passed) = runner
        .baseline(
            baseline_request(root.clone(), "python:3.12-slim"),
            &oracles::pytest_passed(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let target = PythonTarget {
        module: "app".into(),
        callable: "read_file".into(),
        framework: PythonFramework::Generic,
    };
    let (experiment, reproducer) = generated_experiment(
        root.clone(),
        "python:3.12-slim",
        PythonHypothesisKind::PathTraversal,
        &target,
    );
    let evidence = runner
        .execute(experiment, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        classify(&ConfirmationPolicy::default(), &evidence, baseline_passed),
        Verdict::Confirmed
    );
    let replay = reproducer
        .replay(&runner, root, CancellationToken::new())
        .await
        .unwrap();
    assert!(replay.oracle_passed);
    assert_eq!(replay.oracle_passed, evidence.oracle_passed);
    let requests = backend.requests.lock().unwrap();
    assert_eq!(requests.len(), 5);
    assert!(
        requests
            .iter()
            .all(|request| request.image == "python:3.12-slim")
    );
    assert!(requests[1].command[2].contains("../../etc/passwd"));
    assert!(requests[1].command[2].contains("from hypothesis import"));
}

#[tokio::test]
async fn rejected_command_injection_has_clean_negative_control() {
    let root = fixture_root();
    let backend = Arc::new(QueueSandbox::new(&[
        ("1 passed", 0),
        ("EDSA_NOT_REPRODUCED", 0),
        ("EDSA_CONTROL_CLEAN", 0),
    ]));
    let runner = ExperimentRunner::new(backend.clone());
    let (_, baseline) = runner
        .baseline(
            baseline_request(root.clone(), "python:3.12-slim"),
            &oracles::pytest_passed(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let target = PythonTarget {
        module: "app".into(),
        callable: "run_command".into(),
        framework: PythonFramework::Generic,
    };
    let (experiment, _) = generated_experiment(
        root,
        "python:3.12-slim",
        PythonHypothesisKind::CommandInjection,
        &target,
    );
    let evidence = runner
        .execute(experiment, CancellationToken::new())
        .await
        .unwrap();
    assert!(!evidence.oracle_passed);
    assert!(evidence.negative_control_passed);
    assert_eq!(
        classify(&ConfirmationPolicy::default(), &evidence, baseline),
        Verdict::Rejected
    );
    let requests = backend.requests.lock().unwrap();
    assert_eq!(requests[2].environment["EDSA_NEGATIVE_CONTROL"], "1");
}

#[tokio::test]
async fn failed_baseline_keeps_hypothesis_inconclusive() {
    let root = fixture_root();
    let backend = Arc::new(QueueSandbox::new(&[
        ("failed", 1),
        ("EDSA_VULNERABLE", 0),
        ("EDSA_CONTROL_CLEAN", 0),
    ]));
    let runner = ExperimentRunner::new(backend);
    let (_, baseline) = runner
        .baseline(
            baseline_request(root.clone(), "python:3.12-slim"),
            &oracles::pytest_passed(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let target = PythonTarget {
        module: "app".into(),
        callable: "read_file".into(),
        framework: PythonFramework::Generic,
    };
    let (experiment, _) = generated_experiment(
        root,
        "python:3.12-slim",
        PythonHypothesisKind::PathTraversal,
        &target,
    );
    let evidence = runner
        .execute(experiment, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        classify(&ConfirmationPolicy::default(), &evidence, baseline),
        Verdict::Inconclusive
    );
}

#[test]
fn frozen_lockfile_is_selected_without_mutating_the_repository() {
    let inventory = RepositoryInventory {
        schema_version: SCHEMA_VERSION,
        snapshot: RepositorySnapshot::new(".", "revision", "digest", false),
        files: vec![edsa_core::RepositoryFile {
            schema_version: SCHEMA_VERSION,
            relative_path: "uv.lock".into(),
            size_bytes: 1,
            sha256: "digest".into(),
        }],
        exclusions: Vec::new(),
        detection: LanguageDetection {
            schema_version: SCHEMA_VERSION,
            languages: BTreeSet::default(),
            manifests: Vec::new(),
        },
    };
    let plan = environment_plan(&inventory);
    assert_eq!(plan.manager, DependencyManager::Uv);
    assert!(plan.locked);
    assert_eq!(plan.preparation_command, ["uv", "sync", "--frozen"]);
}

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../benchmarks/python/fixture")
        .canonicalize()
        .unwrap()
}
