use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    CommandExecutor, CommandOutput, CommandSpec, ExecutionError, ProcessCommandExecutor,
    SandboxPolicy, executor_arc,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxRequest {
    pub source_root: PathBuf,
    pub image: String,
    pub command: Vec<String>,
    pub environment: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxOutput {
    pub container_name: String,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

#[derive(Clone, Debug)]
pub struct DockerRunner {
    executor: Arc<dyn CommandExecutor>,
    policy: SandboxPolicy,
}

impl DockerRunner {
    #[must_use]
    pub fn new(policy: SandboxPolicy) -> Self {
        Self {
            executor: executor_arc(ProcessCommandExecutor),
            policy,
        }
    }

    #[must_use]
    pub fn with_executor(policy: SandboxPolicy, executor: Arc<dyn CommandExecutor>) -> Self {
        Self { executor, policy }
    }

    /// Runs a command only inside a newly created constrained Docker container.
    ///
    /// The work is owned by a spawned task, so cleanup continues if the caller drops
    /// the returned future. Use `cancellation` for prompt cooperative cancellation.
    ///
    /// # Errors
    /// Returns an error for policy rejection, Docker failures, timeout, cancellation,
    /// or cleanup failure.
    pub async fn run(
        &self,
        request: SandboxRequest,
        cancellation: CancellationToken,
    ) -> Result<SandboxOutput, SandboxError> {
        let runner = self.clone();
        tokio::spawn(async move { runner.run_owned(request, cancellation).await })
            .await
            .map_err(SandboxError::Worker)?
    }

    async fn run_owned(
        &self,
        request: SandboxRequest,
        cancellation: CancellationToken,
    ) -> Result<SandboxOutput, SandboxError> {
        let source_root = self.policy.validate(
            &request.source_root,
            &request.image,
            &request.command,
            &request.environment,
        )?;
        let container_name = format!("edsa-{}", Uuid::new_v4().simple());
        let create = self
            .executor
            .execute(CommandSpec {
                program: "docker".to_owned(),
                arguments: create_arguments(
                    &container_name,
                    &source_root.to_string_lossy(),
                    &request,
                    &self.policy,
                ),
                timeout: Duration::from_secs(30),
                maximum_output_bytes_per_stream: 16 * 1024,
                cancellation: cancellation.clone(),
            })
            .await?;
        require_success("create", &create)?;

        let execution = self
            .executor
            .execute(CommandSpec {
                program: "docker".to_owned(),
                arguments: vec![
                    "start".to_owned(),
                    "--attach".to_owned(),
                    container_name.clone(),
                ],
                timeout: self.policy.timeout,
                maximum_output_bytes_per_stream: self.policy.maximum_output_bytes_per_stream,
                cancellation,
            })
            .await;
        let cleanup = self.cleanup(&container_name).await;

        let output = execution?;
        cleanup?;
        Ok(SandboxOutput {
            container_name,
            exit_code: output.exit_code,
            stdout: output.stdout,
            stderr: output.stderr,
            stdout_truncated: output.stdout_truncated,
            stderr_truncated: output.stderr_truncated,
        })
    }

    async fn cleanup(&self, container_name: &str) -> Result<(), SandboxError> {
        let output = self
            .executor
            .execute(CommandSpec {
                program: "docker".to_owned(),
                arguments: vec![
                    "rm".to_owned(),
                    "--force".to_owned(),
                    container_name.to_owned(),
                ],
                timeout: self.policy.cleanup_timeout,
                maximum_output_bytes_per_stream: 16 * 1024,
                cancellation: CancellationToken::new(),
            })
            .await?;
        require_success("cleanup", &output)
    }
}

fn create_arguments(
    name: &str,
    source_root: &str,
    request: &SandboxRequest,
    policy: &SandboxPolicy,
) -> Vec<String> {
    let mut arguments = vec![
        "create".to_owned(),
        "--name".to_owned(),
        name.to_owned(),
        "--network".to_owned(),
        "none".to_owned(),
        "--read-only".to_owned(),
        "--cap-drop".to_owned(),
        "ALL".to_owned(),
        "--security-opt".to_owned(),
        "no-new-privileges".to_owned(),
        "--pids-limit".to_owned(),
        policy.pids_limit.to_string(),
        "--memory".to_owned(),
        policy.memory_limit.clone(),
        "--cpus".to_owned(),
        policy.cpu_limit.clone(),
        "--user".to_owned(),
        policy.run_as_user.clone(),
        "--mount".to_owned(),
        format!("type=bind,source={source_root},target=/workspace,readonly"),
        "--tmpfs".to_owned(),
        format!("/tmp:rw,noexec,nosuid,size={}", policy.tmpfs_size),
        "--workdir".to_owned(),
        "/workspace".to_owned(),
        "--stop-timeout".to_owned(),
        "1".to_owned(),
    ];
    for (name, value) in &request.environment {
        arguments.extend(["--env".to_owned(), format!("{name}={value}")]);
    }
    arguments.push(request.image.clone());
    arguments.extend(request.command.iter().cloned());
    arguments
}

fn require_success(operation: &'static str, output: &CommandOutput) -> Result<(), SandboxError> {
    if output.exit_code == Some(0) {
        Ok(())
    } else {
        Err(SandboxError::Docker {
            operation,
            exit_code: output.exit_code,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("sandbox policy rejected the request: {0}")]
    Policy(#[from] crate::PolicyError),
    #[error("host command failed: {0}")]
    Execution(#[from] ExecutionError),
    #[error("Docker {operation} failed with {exit_code:?}: {stderr}")]
    Docker {
        operation: &'static str,
        exit_code: Option<i32>,
        stderr: String,
    },
    #[error("sandbox worker failed: {0}")]
    Worker(tokio::task::JoinError),
}
