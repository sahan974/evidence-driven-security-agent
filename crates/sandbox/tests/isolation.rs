use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use edsa_sandbox::{
    CommandExecutor, CommandOutput, CommandSpec, DockerRunner, ExecutionError, SandboxPolicy,
    SandboxRequest,
};
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug)]
enum FakeStep {
    Output(CommandOutput),
    WaitForCancellation,
    Timeout,
}

#[derive(Debug, Default)]
struct FakeExecutor {
    steps: Mutex<VecDeque<FakeStep>>,
    calls: Mutex<Vec<CommandSpec>>,
}

impl FakeExecutor {
    fn new(steps: Vec<FakeStep>) -> Arc<Self> {
        Arc::new(Self {
            steps: Mutex::new(steps.into()),
            calls: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> Vec<CommandSpec> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl CommandExecutor for FakeExecutor {
    async fn execute(&self, specification: CommandSpec) -> Result<CommandOutput, ExecutionError> {
        self.calls.lock().unwrap().push(specification.clone());
        let step = self
            .steps
            .lock()
            .unwrap()
            .pop_front()
            .expect("missing fake step");
        match step {
            FakeStep::Output(output) => Ok(output),
            FakeStep::WaitForCancellation => {
                specification.cancellation.cancelled().await;
                Err(ExecutionError::Cancelled)
            }
            FakeStep::Timeout => Err(ExecutionError::Timeout(specification.timeout)),
        }
    }
}

fn success() -> CommandOutput {
    CommandOutput {
        exit_code: Some(0),
        stdout: Vec::new(),
        stderr: Vec::new(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn request(source_root: &std::path::Path) -> SandboxRequest {
    SandboxRequest {
        source_root: source_root.to_owned(),
        image: "alpine:3.20".to_owned(),
        command: vec!["sh".to_owned(), "-c".to_owned(), "true".to_owned()],
        environment: BTreeMap::new(),
    }
}

#[tokio::test]
async fn fake_executor_receives_hardened_create_and_guaranteed_cleanup() {
    let directory = tempdir().unwrap();
    let executor = FakeExecutor::new(vec![
        FakeStep::Output(success()),
        FakeStep::Output(success()),
        FakeStep::Output(success()),
    ]);
    let runner = DockerRunner::with_executor(SandboxPolicy::default(), executor.clone());
    let output = runner
        .run(request(directory.path()), CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        output.exit_code,
        Some(0),
        "sandbox stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let calls = executor.calls();
    assert_eq!(calls.len(), 3);
    let create = &calls[0].arguments;
    for expected in [
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--pids-limit",
        "--memory",
        "--cpus",
        "--user",
    ] {
        assert!(
            create.iter().any(|argument| argument == expected),
            "missing {expected}"
        );
    }
    assert!(
        create
            .iter()
            .any(|argument| argument.contains("target=/workspace,readonly"))
    );
    assert_eq!(calls[2].arguments[0], "rm");
    assert_eq!(calls[2].arguments[2], output.container_name);
}

#[tokio::test]
async fn cancellation_still_removes_the_container() {
    let directory = tempdir().unwrap();
    let executor = FakeExecutor::new(vec![
        FakeStep::Output(success()),
        FakeStep::WaitForCancellation,
        FakeStep::Output(success()),
    ]);
    let runner = DockerRunner::with_executor(SandboxPolicy::default(), executor.clone());
    let cancellation = CancellationToken::new();
    let task = tokio::spawn({
        let cancellation = cancellation.clone();
        async move { runner.run(request(directory.path()), cancellation).await }
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    cancellation.cancel();
    assert!(matches!(
        task.await.unwrap(),
        Err(edsa_sandbox::docker::SandboxError::Execution(
            ExecutionError::Cancelled
        ))
    ));
    assert_eq!(executor.calls().last().unwrap().arguments[0], "rm");
}

#[tokio::test]
async fn timeout_still_removes_the_container() {
    let directory = tempdir().unwrap();
    let executor = FakeExecutor::new(vec![
        FakeStep::Output(success()),
        FakeStep::Timeout,
        FakeStep::Output(success()),
    ]);
    let runner = DockerRunner::with_executor(SandboxPolicy::default(), executor.clone());
    let result = runner
        .run(request(directory.path()), CancellationToken::new())
        .await;
    assert!(matches!(
        result,
        Err(edsa_sandbox::docker::SandboxError::Execution(
            ExecutionError::Timeout(_)
        ))
    ));
    assert_eq!(executor.calls().last().unwrap().arguments[0], "rm");
}

#[test]
fn policy_rejects_api_keys_even_if_allowlisted() {
    let directory = tempdir().unwrap();
    let mut policy = SandboxPolicy::default();
    policy
        .allowed_environment
        .insert("MODEL_API_KEY".to_owned());
    let mut request = request(directory.path());
    request
        .environment
        .insert("MODEL_API_KEY".to_owned(), "secret".to_owned());
    assert!(
        policy
            .validate(
                &request.source_root,
                &request.image,
                &request.command,
                &request.environment
            )
            .is_err()
    );
}

#[tokio::test]
#[ignore = "requires Docker Desktop with Linux containers and alpine:3.20"]
async fn docker_enforces_isolation_and_cleanup() {
    let directory = tempdir().unwrap();
    std::fs::write(directory.path().join("input.txt"), "original").unwrap();
    let runner = DockerRunner::new(SandboxPolicy {
        timeout: Duration::from_secs(15),
        ..SandboxPolicy::default()
    });

    let mut sandbox_request = request(directory.path());
    sandbox_request.command = vec![
        "sh".to_owned(),
        "-c".to_owned(),
        "! touch /workspace/write-probe && test -z \"$MODEL_API_KEY\" && ! wget -T 1 -qO- https://example.com && test \"$(id -u)\" = 65532 && test \"$(awk '/CapEff/{print $2}' /proc/1/status)\" = 0000000000000000 && test \"$(awk '/NoNewPrivs/{print $2}' /proc/1/status)\" = 1 && test \"$(cat /sys/fs/cgroup/pids.max)\" = 128 && test \"$(cat /sys/fs/cgroup/memory.max)\" = 536870912 && test \"$(cat /sys/fs/cgroup/cpu.max)\" = \"100000 100000\"".to_owned(),
    ];
    let output = runner
        .run(sandbox_request, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        output.exit_code,
        Some(0),
        "sandbox stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(directory.path().join("input.txt")).unwrap(),
        "original"
    );

    let status = tokio::process::Command::new("docker")
        .args(["inspect", &output.container_name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .unwrap();
    assert!(
        !status.success(),
        "container must be removed after execution"
    );
}
