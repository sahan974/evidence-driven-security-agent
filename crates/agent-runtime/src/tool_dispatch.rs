use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use edsa_core::{RepositoryInventory, resolve_repository_path};
use edsa_evidence::{ArtifactError, ArtifactStore};
use thiserror::Error;

use crate::roles::{
    AgentRole, RoleConfiguration, SearchMatch, ToolCapability, ToolRequest, ToolResult,
};

const MAXIMUM_READ_BYTES: u64 = 64 * 1024;
const MAXIMUM_ARTIFACT_READ_BYTES: u64 = 64 * 1024;
const MAXIMUM_SEARCH_MATCHES: u32 = 100;

#[derive(Debug)]
pub struct ToolDispatcher {
    repository_root: PathBuf,
    admitted_files: BTreeSet<String>,
    configurations: BTreeMap<AgentRole, RoleConfiguration>,
}

impl ToolDispatcher {
    #[must_use]
    pub fn new(
        repository_root: impl Into<PathBuf>,
        inventory: &RepositoryInventory,
        configurations: BTreeMap<AgentRole, RoleConfiguration>,
    ) -> Self {
        Self {
            repository_root: repository_root.into(),
            admitted_files: inventory
                .files
                .iter()
                .map(|file| file.relative_path.clone())
                .collect(),
            configurations,
        }
    }

    /// Validates a role capability and executes a bounded repository tool.
    ///
    /// # Errors
    /// Returns an error for role-policy violations, unsafe paths, excessive limits,
    /// tools that require run context, or I/O failures.
    pub fn dispatch(
        &self,
        role: AgentRole,
        request: &ToolRequest,
    ) -> Result<ToolResult, ToolDispatchError> {
        self.dispatch_inner(role, request, None)
    }

    /// Executes a bounded tool with access to one run's verified artifact store.
    ///
    /// # Errors
    /// Returns an error for role-policy violations, invalid limits, unverified
    /// artifacts, permanently denied direct execution, or I/O failures.
    pub fn dispatch_with_evidence(
        &self,
        role: AgentRole,
        request: &ToolRequest,
        artifacts: &ArtifactStore,
    ) -> Result<ToolResult, ToolDispatchError> {
        self.dispatch_inner(role, request, Some(artifacts))
    }

    fn dispatch_inner(
        &self,
        role: AgentRole,
        request: &ToolRequest,
        artifacts: Option<&ArtifactStore>,
    ) -> Result<ToolResult, ToolDispatchError> {
        let capability = request.capability();
        let configuration = self
            .configurations
            .get(&role)
            .ok_or(ToolDispatchError::UnknownRole(role))?;
        if !configuration.allowed_tools.contains(&capability) {
            return Err(ToolDispatchError::Forbidden { role, capability });
        }
        match request {
            ToolRequest::ReadRepositoryFile {
                relative_path,
                start_byte,
                maximum_bytes,
            } => self.read_file(relative_path, *start_byte, *maximum_bytes),
            ToolRequest::SearchRepository {
                query,
                path_prefix,
                maximum_matches,
            } => self.search(query, path_prefix.as_deref(), *maximum_matches),
            ToolRequest::RunSandboxExperiment { .. } => {
                Err(ToolDispatchError::DirectExperimentForbidden)
            }
            ToolRequest::ReadEvidenceArtifact {
                sha256,
                maximum_bytes,
            } => Self::read_evidence_artifact(
                artifacts.ok_or(ToolDispatchError::MissingEvidenceContext)?,
                sha256,
                *maximum_bytes,
            ),
            ToolRequest::ProposePatch { .. } => Err(ToolDispatchError::PatchWorkflowUnavailable),
        }
    }

    fn read_evidence_artifact(
        artifacts: &ArtifactStore,
        sha256: &str,
        maximum_bytes: u64,
    ) -> Result<ToolResult, ToolDispatchError> {
        if maximum_bytes == 0 || maximum_bytes > MAXIMUM_ARTIFACT_READ_BYTES {
            return Err(ToolDispatchError::ArtifactReadLimit(maximum_bytes));
        }

        // ArtifactStore::get validates the digest, confines the resolved path,
        // reads the complete object, and verifies its content hash. Truncation
        // happens only after that integrity check succeeds.
        let bytes = artifacts.get(sha256)?;
        let retained = usize::try_from(maximum_bytes)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        Ok(ToolResult::EvidenceArtifact {
            sha256: sha256.to_owned(),
            media_type: "application/octet-stream".to_owned(),
            content: bytes[..retained].to_vec(),
            truncated: retained < bytes.len(),
        })
    }

    fn read_file(
        &self,
        relative_path: &str,
        start_byte: u64,
        maximum_bytes: u64,
    ) -> Result<ToolResult, ToolDispatchError> {
        self.admit_path(relative_path)?;
        if maximum_bytes == 0 || maximum_bytes > MAXIMUM_READ_BYTES {
            return Err(ToolDispatchError::ReadLimit(maximum_bytes));
        }
        let path = resolve_repository_path(&self.repository_root, Path::new(relative_path))?;
        let bytes = fs::read(path)?;
        let start = usize::try_from(start_byte).map_err(|_| ToolDispatchError::OffsetOverflow)?;
        if start > bytes.len() {
            return Err(ToolDispatchError::OffsetPastEnd);
        }
        let requested = usize::try_from(maximum_bytes).unwrap_or(usize::MAX);
        let end = start.saturating_add(requested).min(bytes.len());
        Ok(ToolResult::RepositoryFile {
            relative_path: relative_path.to_owned(),
            content: String::from_utf8_lossy(&bytes[start..end]).into_owned(),
            truncated: end < bytes.len(),
        })
    }

    fn search(
        &self,
        query: &str,
        path_prefix: Option<&str>,
        maximum_matches: u32,
    ) -> Result<ToolResult, ToolDispatchError> {
        if query.is_empty() {
            return Err(ToolDispatchError::EmptyQuery);
        }
        if maximum_matches == 0 || maximum_matches > MAXIMUM_SEARCH_MATCHES {
            return Err(ToolDispatchError::SearchLimit(maximum_matches));
        }
        let mut matches = Vec::new();
        let mut truncated = false;
        for relative_path in &self.admitted_files {
            if path_prefix.is_some_and(|prefix| !relative_path.starts_with(prefix)) {
                continue;
            }
            let path = resolve_repository_path(&self.repository_root, Path::new(relative_path))?;
            let text = String::from_utf8_lossy(&fs::read(path)?).into_owned();
            for (index, line) in text.lines().enumerate() {
                if line.contains(query) {
                    if matches.len() == usize::try_from(maximum_matches).unwrap_or(usize::MAX) {
                        truncated = true;
                        break;
                    }
                    matches.push(SearchMatch {
                        relative_path: relative_path.clone(),
                        line: u32::try_from(index + 1).unwrap_or(u32::MAX),
                        excerpt: line.chars().take(240).collect(),
                    });
                }
            }
            if truncated {
                break;
            }
        }
        Ok(ToolResult::SearchMatches { matches, truncated })
    }

    fn admit_path(&self, relative_path: &str) -> Result<(), ToolDispatchError> {
        if self.admitted_files.contains(relative_path) {
            Ok(())
        } else {
            Err(ToolDispatchError::UnadmittedPath(relative_path.to_owned()))
        }
    }
}

#[derive(Debug, Error)]
pub enum ToolDispatchError {
    #[error("role configuration is missing: {0:?}")]
    UnknownRole(AgentRole),
    #[error("role {role:?} is not allowed to use {capability:?}")]
    Forbidden {
        role: AgentRole,
        capability: ToolCapability,
    },
    #[error("repository path was not admitted: {0}")]
    UnadmittedPath(String),
    #[error("repository read limit must be in 1..={MAXIMUM_READ_BYTES}, found {0}")]
    ReadLimit(u64),
    #[error("evidence artifact read limit must be in 1..={MAXIMUM_ARTIFACT_READ_BYTES}, found {0}")]
    ArtifactReadLimit(u64),
    #[error("repository search limit must be in 1..={MAXIMUM_SEARCH_MATCHES}, found {0}")]
    SearchLimit(u32),
    #[error("repository search query cannot be empty")]
    EmptyQuery,
    #[error("repository read offset cannot be represented")]
    OffsetOverflow,
    #[error("repository read offset is past the end of the file")]
    OffsetPastEnd,
    #[error("evidence artifact reads require the current run's artifact store")]
    MissingEvidenceContext,
    #[error(
        "model-supplied experiment commands are forbidden; experiments must use admitted typed adapter operations"
    )]
    DirectExperimentForbidden,
    #[error("the verified patch workflow is not installed")]
    PatchWorkflowUnavailable,
    #[error("artifact verification failed: {0}")]
    Artifact(#[from] ArtifactError),
    #[error("repository path policy failed: {0}")]
    PathPolicy(#[from] edsa_core::PathPolicyError),
    #[error("tool I/O failed: {0}")]
    Io(#[from] std::io::Error),
}
