use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionReason {
    GitMetadata,
    Generated,
    Vendor,
    SecretLike,
    Binary,
    TooLarge,
    UnsupportedFileType,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExcludedPath {
    pub schema_version: u16,
    pub relative_path: String,
    pub reason: ExclusionReason,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryPolicy {
    pub maximum_file_bytes: u64,
    pub generated_directories: BTreeSet<String>,
    pub vendor_directories: BTreeSet<String>,
    pub binary_extensions: BTreeSet<String>,
    pub secret_file_names: BTreeSet<String>,
}

impl Default for RepositoryPolicy {
    fn default() -> Self {
        Self {
            maximum_file_bytes: 5 * 1024 * 1024,
            generated_directories: [
                ".cache",
                ".next",
                ".pytest_cache",
                "__pycache__",
                "build",
                "coverage",
                "dist",
                "target",
            ]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
            vendor_directories: ["node_modules", "vendor", ".venv", "venv"]
                .into_iter()
                .map(ToOwned::to_owned)
                .collect(),
            binary_extensions: [
                "7z", "a", "avi", "bin", "bmp", "class", "dll", "dylib", "exe", "gif", "gz", "ico",
                "jar", "jpeg", "jpg", "lib", "mov", "mp3", "mp4", "o", "obj", "pdf", "png", "so",
                "tar", "wasm", "webp", "woff", "woff2", "zip",
            ]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
            secret_file_names: [
                ".env",
                ".env.local",
                ".npmrc",
                ".pypirc",
                "credentials.json",
                "id_dsa",
                "id_ed25519",
                "id_rsa",
            ]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
        }
    }
}

impl RepositoryPolicy {
    #[must_use]
    pub fn excluded_directory(&self, name: &str) -> Option<ExclusionReason> {
        if name == ".git" {
            Some(ExclusionReason::GitMetadata)
        } else if self.generated_directories.contains(name) {
            Some(ExclusionReason::Generated)
        } else if self.vendor_directories.contains(name) {
            Some(ExclusionReason::Vendor)
        } else {
            None
        }
    }

    #[must_use]
    pub fn excluded_file(&self, path: &Path, size: u64, prefix: &[u8]) -> Option<ExclusionReason> {
        let name = path.file_name()?.to_string_lossy();
        let lowercase = name.to_ascii_lowercase();
        let extension = path
            .extension()
            .map(|value| value.to_string_lossy().to_ascii_lowercase());
        let secret_extension = extension
            .as_deref()
            .is_some_and(|value| ["pem", "key", "p12", "pfx"].contains(&value));
        if self.secret_file_names.contains(lowercase.as_str())
            || lowercase.starts_with(".env.")
            || secret_extension
        {
            return Some(ExclusionReason::SecretLike);
        }
        if size > self.maximum_file_bytes {
            return Some(ExclusionReason::TooLarge);
        }
        if extension.is_some_and(|value| self.binary_extensions.contains(&value))
            || prefix.contains(&0)
        {
            return Some(ExclusionReason::Binary);
        }
        None
    }
}

/// Resolves a portable relative path while enforcing repository containment.
///
/// # Errors
/// Returns an error for absolute paths, parent traversal, symlinks, or missing targets.
pub fn resolve_repository_path(root: &Path, relative: &Path) -> Result<PathBuf, PathPolicyError> {
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(PathPolicyError::Escape(relative.to_path_buf()));
    }
    let root = dunce::canonicalize(root).map_err(PathPolicyError::Io)?;
    let candidate = root.join(relative);
    let metadata = std::fs::symlink_metadata(&candidate).map_err(PathPolicyError::Io)?;
    if metadata.file_type().is_symlink() {
        return Err(PathPolicyError::Symlink(relative.to_path_buf()));
    }
    let resolved = dunce::canonicalize(&candidate).map_err(PathPolicyError::Io)?;
    if !resolved.starts_with(&root) {
        return Err(PathPolicyError::Escape(relative.to_path_buf()));
    }
    Ok(resolved)
}

/// Validates an archive member name before extraction.
///
/// # Errors
/// Returns an error for absolute paths, parent traversal, or platform path prefixes.
pub fn validate_archive_entry(path: &Path) -> Result<(), PathPolicyError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(PathPolicyError::Escape(path.to_path_buf()));
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum PathPolicyError {
    #[error("path escapes the authorized repository: {0:?}")]
    Escape(PathBuf),
    #[error("symbolic links are not accepted during repository ingestion: {0:?}")]
    Symlink(PathBuf),
    #[error("path inspection failed: {0}")]
    Io(std::io::Error),
}
