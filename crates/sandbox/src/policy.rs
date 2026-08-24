use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxPolicy {
    pub network_enabled: bool,
    pub source_read_only: bool,
    pub run_as_user: String,
    pub cpu_limit: String,
    pub memory_limit: String,
    pub pids_limit: u32,
    pub timeout: Duration,
    pub cleanup_timeout: Duration,
    pub maximum_output_bytes_per_stream: usize,
    pub tmpfs_size: String,
    pub allowed_environment: BTreeSet<String>,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            network_enabled: false,
            source_read_only: true,
            run_as_user: "65532:65532".to_owned(),
            cpu_limit: "1.0".to_owned(),
            memory_limit: "512m".to_owned(),
            pids_limit: 128,
            timeout: Duration::from_secs(60),
            cleanup_timeout: Duration::from_secs(15),
            maximum_output_bytes_per_stream: 1024 * 1024,
            tmpfs_size: "64m".to_owned(),
            allowed_environment: BTreeSet::new(),
        }
    }
}

impl SandboxPolicy {
    /// Validates a sandbox request and returns the canonical source directory.
    ///
    /// # Errors
    /// Returns an error for unsafe policy values, paths, commands, or environment variables.
    pub fn validate(
        &self,
        source_root: &Path,
        image: &str,
        command: &[String],
        environment: &BTreeMap<String, String>,
    ) -> Result<PathBuf, PolicyError> {
        if !self.source_read_only {
            return Err(PolicyError::WritableSourceForbidden);
        }
        if self.network_enabled {
            return Err(PolicyError::NetworkForbidden);
        }
        if image.trim().is_empty() || image.starts_with('-') {
            return Err(PolicyError::InvalidImage);
        }
        if command.is_empty() || command[0].trim().is_empty() {
            return Err(PolicyError::EmptyCommand);
        }
        if self.pids_limit == 0
            || self.timeout.is_zero()
            || self.maximum_output_bytes_per_stream == 0
        {
            return Err(PolicyError::InvalidLimit);
        }
        for name in environment.keys() {
            if sensitive_environment_name(name) {
                return Err(PolicyError::SensitiveEnvironment(name.clone()));
            }
            if !self.allowed_environment.contains(name) {
                return Err(PolicyError::EnvironmentNotAllowed(name.clone()));
            }
        }
        let source_root = dunce::canonicalize(source_root).map_err(PolicyError::SourceRoot)?;
        if !source_root.is_dir() {
            return Err(PolicyError::SourceNotDirectory);
        }
        if source_root.to_string_lossy().contains(',') {
            return Err(PolicyError::UnsupportedSourcePath);
        }
        Ok(source_root)
    }
}

fn sensitive_environment_name(name: &str) -> bool {
    let uppercase = name.to_ascii_uppercase();
    ["KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"]
        .iter()
        .any(|fragment| uppercase.contains(fragment))
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("source repository must be mounted read-only")]
    WritableSourceForbidden,
    #[error("sandbox network access is forbidden by the current security boundary")]
    NetworkForbidden,
    #[error("container image is invalid")]
    InvalidImage,
    #[error("sandbox command cannot be empty")]
    EmptyCommand,
    #[error("sandbox resource limit is invalid")]
    InvalidLimit,
    #[error("environment variable is not allowed: {0}")]
    EnvironmentNotAllowed(String),
    #[error("sensitive environment variable can never enter a sandbox: {0}")]
    SensitiveEnvironment(String),
    #[error("source root could not be resolved: {0}")]
    SourceRoot(std::io::Error),
    #[error("source root is not a directory")]
    SourceNotDirectory,
    #[error("source path contains characters unsupported by safe Docker mount syntax")]
    UnsupportedSourcePath,
}
