use std::collections::{BTreeSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use edsa_adapter_sdk::{ExperimentRunner, SandboxBackend, classify};
use edsa_adapter_typescript::{
    NodeEnvironmentPlan, NodeHypothesisKind, NodeTarget, PackageManager, TestRunner,
    baseline_request, environment_plan, generated_experiment, oracles,
};
use edsa_core::{
    ConfirmationPolicy, LanguageDetection, RepositoryFile, RepositoryInventory, RepositorySnapshot,
    SCHEMA_VERSION, Verdict,
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

#[test]
fn npm_and_vitest_are_selected_from_repository_files() {
    let root = fixture_root();
    let inventory = fixture_inventory(&["package.json", "package-lock.json", "app.js"]);
    let plan = environment_plan(&root, &inventory).unwrap();
    assert_eq!(plan.manager, PackageManager::Npm);
    assert_eq!(plan.test_runner, TestRunner::Vitest);
    assert_eq!(plan.install_command[0..2], ["npm", "ci"]);
    assert!(plan.install_command.contains(&"--ignore-scripts".into()));
}

#[test]
fn missing_lockfile_is_rejected_instead_of_mutating_dependencies() {
    let inventory = fixture_inventory(&["package.json", "app.js"]);
    assert!(environment_plan(&fixture_root(), &inventory).is_err());
}

#[test]
fn baseline_uses_the_lockfile_selected_package_manager() {
    for (manager, expected) in [
        (PackageManager::Pnpm, "pnpm"),
        (PackageManager::Yarn, "yarn"),
    ] {
        let plan = NodeEnvironmentPlan {
            image: "node:22-slim".into(),
            manager,
            lockfile: "lockfile".into(),
            install_command: Vec::new(),
            test_runner: TestRunner::Jest,
        };
        assert_eq!(baseline_request(fixture_root(), &plan).command[0], expected);
    }
}

#[tokio::test]
async fn confirmed_path_traversal_replays_the_recorded_oracle() {
    let root = fixture_root();
    let plan = environment_plan(
        &root,
        &fixture_inventory(&["package.json", "package-lock.json", "app.js"]),
    )
    .unwrap();
    let backend = Arc::new(QueueSandbox::new(&[
        ("tests passed", 0),
        ("EDSA_VULNERABLE", 0),
        ("EDSA_CONTROL_CLEAN", 0),
        ("EDSA_VULNERABLE", 0),
        ("EDSA_CONTROL_CLEAN", 0),
    ]));
    let runner = ExperimentRunner::new(backend.clone());
    let (_, baseline) = runner
        .baseline(
            baseline_request(root.clone(), &plan),
            &oracles::test_suite_passed(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let target = NodeTarget {
        module: "./app.js".into(),
        callable: "readUserFile".into(),
    };
    let (experiment, reproducer) = generated_experiment(
        root.clone(),
        &plan.image,
        NodeHypothesisKind::PathTraversal,
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
        .replay(&runner, root, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(replay.oracle_passed, evidence.oracle_passed);
    let requests = backend.requests.lock().unwrap();
    assert!(requests[1].command[3].contains("fast-check"));
    assert!(requests[1].command[3].contains("../../etc/passwd"));
}

#[tokio::test]
async fn ssrf_uses_only_an_in_sandbox_loopback_callback() {
    let root = fixture_root();
    let backend = Arc::new(QueueSandbox::new(&[
        ("tests passed", 0),
        ("EDSA_VULNERABLE", 0),
        ("EDSA_CONTROL_CLEAN", 0),
    ]));
    let runner = ExperimentRunner::new(backend.clone());
    let plan = environment_plan(
        &root,
        &fixture_inventory(&["package.json", "package-lock.json", "app.js"]),
    )
    .unwrap();
    let (_, baseline) = runner
        .baseline(
            baseline_request(root.clone(), &plan),
            &oracles::test_suite_passed(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let target = NodeTarget {
        module: "./app.js".into(),
        callable: "fetchUserUrl".into(),
    };
    let (experiment, _) =
        generated_experiment(root, &plan.image, NodeHypothesisKind::Ssrf, &target);
    let evidence = runner
        .execute(experiment, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        classify(&ConfirmationPolicy::default(), &evidence, baseline),
        Verdict::Confirmed
    );
    let requests = backend.requests.lock().unwrap();
    let script = &requests[1].command[3];
    assert!(script.contains("127.0.0.1"));
    assert!(!script.contains("example.com"));
    assert_eq!(requests[2].environment["EDSA_NEGATIVE_CONTROL"], "1");
}

#[tokio::test]
async fn non_reproduced_ssrf_is_rejected_with_a_clean_control() {
    let root = fixture_root();
    let backend = Arc::new(QueueSandbox::new(&[
        ("tests passed", 0),
        ("EDSA_NOT_REPRODUCED", 0),
        ("EDSA_CONTROL_CLEAN", 0),
    ]));
    let runner = ExperimentRunner::new(backend);
    let plan = environment_plan(
        &root,
        &fixture_inventory(&["package.json", "package-lock.json", "app.js"]),
    )
    .unwrap();
    let (_, baseline) = runner
        .baseline(
            baseline_request(root.clone(), &plan),
            &oracles::test_suite_passed(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let target = NodeTarget {
        module: "./app.js".into(),
        callable: "fetchUserUrl".into(),
    };
    let (experiment, _) =
        generated_experiment(root, &plan.image, NodeHypothesisKind::Ssrf, &target);
    let evidence = runner
        .execute(experiment, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        classify(&ConfirmationPolicy::default(), &evidence, baseline),
        Verdict::Rejected
    );
}

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../benchmarks/typescript/fixture")
        .canonicalize()
        .unwrap()
}

fn fixture_inventory(paths: &[&str]) -> RepositoryInventory {
    RepositoryInventory {
        schema_version: SCHEMA_VERSION,
        snapshot: RepositorySnapshot::new(".", "revision", "digest", false),
        files: paths
            .iter()
            .map(|path| RepositoryFile {
                schema_version: SCHEMA_VERSION,
                relative_path: (*path).into(),
                size_bytes: 1,
                sha256: "digest".into(),
            })
            .collect(),
        exclusions: Vec::new(),
        detection: LanguageDetection {
            schema_version: SCHEMA_VERSION,
            languages: BTreeSet::default(),
            manifests: Vec::new(),
        },
    }
}
