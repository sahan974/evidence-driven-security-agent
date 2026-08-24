use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use edsa_core::Signal;
use edsa_sandbox::{CommandExecutor, CommandSpec, ExecutionError};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::{SarifError, import_sarif};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemgrepOptions {
    pub executable: String,
    pub configuration: String,
    pub timeout: Duration,
    pub maximum_output_bytes: usize,
}

impl Default for SemgrepOptions {
    fn default() -> Self {
        Self {
            executable: "semgrep".into(),
            configuration: "auto".into(),
            timeout: Duration::from_secs(300),
            maximum_output_bytes: 16 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
#[error("optional capability `{capability}` is unavailable: {reason}")]
pub struct CapabilityLimitation {
    pub capability: String,
    pub reason: String,
}

/// Runs optional Semgrep and imports its SARIF output. A missing binary is a
/// capability limitation, not a failure of built-in signal collection.
///
/// # Errors
/// Returns a typed limitation or execution, output-bound, exit-status, path, or
/// SARIF parsing error.
pub async fn run_semgrep(
    executor: Arc<dyn CommandExecutor>,
    root: &Path,
    options: &SemgrepOptions,
    cancellation: CancellationToken,
) -> Result<Vec<Signal>, SemgrepError> {
    let root = root.to_str().ok_or(SemgrepError::NonUnicodePath)?;
    let output = executor
        .execute(CommandSpec {
            program: options.executable.clone(),
            arguments: vec![
                "scan".into(),
                "--sarif".into(),
                "--config".into(),
                options.configuration.clone(),
                "--quiet".into(),
                root.into(),
            ],
            timeout: options.timeout,
            maximum_output_bytes_per_stream: options.maximum_output_bytes,
            cancellation,
        })
        .await
        .map_err(|error| match error {
            ExecutionError::Spawn(source) if source.kind() == std::io::ErrorKind::NotFound => {
                SemgrepError::Unavailable(CapabilityLimitation {
                    capability: "semgrep".into(),
                    reason: "binary was not found on PATH".into(),
                })
            }
            other => SemgrepError::Execution(other),
        })?;
    if output.stdout_truncated {
        return Err(SemgrepError::Truncated);
    }
    if output.exit_code != Some(0) {
        return Err(SemgrepError::Exit {
            code: output.exit_code,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    import_sarif(&output.stdout, "semgrep:stdout").map_err(SemgrepError::Sarif)
}

#[derive(Debug, Error)]
pub enum SemgrepError {
    #[error(transparent)]
    Unavailable(#[from] CapabilityLimitation),
    #[error("Semgrep execution failed: {0}")]
    Execution(ExecutionError),
    #[error("Semgrep exited with {code:?}: {stderr}")]
    Exit { code: Option<i32>, stderr: String },
    #[error("Semgrep SARIF output exceeded its configured bound")]
    Truncated,
    #[error("Semgrep emitted invalid SARIF: {0}")]
    Sarif(SarifError),
    #[error("repository path is not Unicode")]
    NonUnicodePath,
}
