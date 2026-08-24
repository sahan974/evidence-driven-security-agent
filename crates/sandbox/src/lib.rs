//! Constrained execution of untrusted repository code.

pub mod docker;
pub mod policy;

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

pub use docker::{DockerRunner, SandboxOutput, SandboxRequest};
pub use policy::{PolicyError, SandboxPolicy};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    pub program: String,
    pub arguments: Vec<String>,
    pub timeout: Duration,
    pub maximum_output_bytes_per_stream: usize,
    pub cancellation: CancellationToken,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutput {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

#[async_trait]
pub trait CommandExecutor: std::fmt::Debug + Send + Sync {
    /// Executes one host command under explicit limits.
    ///
    /// # Errors
    /// Returns a typed error for spawning, timeout, cancellation, or I/O failure.
    async fn execute(&self, specification: CommandSpec) -> Result<CommandOutput, ExecutionError>;
}

#[derive(Clone, Debug, Default)]
pub struct ProcessCommandExecutor;

#[async_trait]
impl CommandExecutor for ProcessCommandExecutor {
    async fn execute(&self, specification: CommandSpec) -> Result<CommandOutput, ExecutionError> {
        let mut child = Command::new(&specification.program)
            .args(&specification.arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(ExecutionError::Spawn)?;
        let stdout = child.stdout.take().ok_or(ExecutionError::MissingPipe)?;
        let stderr = child.stderr.take().ok_or(ExecutionError::MissingPipe)?;
        let stdout_task = tokio::spawn(read_bounded(
            stdout,
            specification.maximum_output_bytes_per_stream,
        ));
        let stderr_task = tokio::spawn(read_bounded(
            stderr,
            specification.maximum_output_bytes_per_stream,
        ));

        let completion = tokio::select! {
            result = child.wait() => result.map_err(ExecutionError::Io),
            () = tokio::time::sleep(specification.timeout) => Err(ExecutionError::Timeout(specification.timeout)),
            () = specification.cancellation.cancelled() => Err(ExecutionError::Cancelled),
        };
        if completion.is_err() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        let (stdout, stdout_truncated) = stdout_task
            .await
            .map_err(ExecutionError::ReaderTask)?
            .map_err(ExecutionError::Io)?;
        let (stderr, stderr_truncated) = stderr_task
            .await
            .map_err(ExecutionError::ReaderTask)?
            .map_err(ExecutionError::Io)?;
        let status = completion?;
        Ok(CommandOutput {
            exit_code: status.code(),
            stdout,
            stderr,
            stdout_truncated,
            stderr_truncated,
        })
    }
}

async fn read_bounded(
    mut reader: impl AsyncRead + Unpin,
    limit: usize,
) -> Result<(Vec<u8>, bool), std::io::Error> {
    let mut stored = Vec::with_capacity(limit.min(8 * 1024));
    let mut buffer = [0_u8; 8 * 1024];
    let mut truncated = false;
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        let remaining = limit.saturating_sub(stored.len());
        let retained = count.min(remaining);
        stored.extend_from_slice(&buffer[..retained]);
        truncated |= retained < count;
    }
    Ok((stored, truncated))
}

pub(crate) fn executor_arc(executor: impl CommandExecutor + 'static) -> Arc<dyn CommandExecutor> {
    Arc::new(executor)
}

#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("failed to spawn command: {0}")]
    Spawn(std::io::Error),
    #[error("command I/O failed: {0}")]
    Io(std::io::Error),
    #[error("command timed out after {0:?}")]
    Timeout(Duration),
    #[error("command was cancelled")]
    Cancelled,
    #[error("command output pipe was unavailable")]
    MissingPipe,
    #[error("output reader task failed: {0}")]
    ReaderTask(tokio::task::JoinError),
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::read_bounded;

    #[tokio::test]
    async fn bounded_reader_drains_but_retains_only_the_limit() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let write = tokio::spawn(async move {
            writer.write_all(b"0123456789").await.unwrap();
        });
        let (bytes, truncated) = read_bounded(reader, 4).await.unwrap();
        write.await.unwrap();
        assert_eq!(bytes, b"0123");
        assert!(truncated);
    }
}
