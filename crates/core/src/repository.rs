use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    ExcludedPath, LanguageDetection, RepositoryPolicy, RepositorySnapshot, SCHEMA_VERSION, detect,
    resolve_repository_path,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepositoryFile {
    pub schema_version: u16,
    pub relative_path: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepositoryInventory {
    pub schema_version: u16,
    pub snapshot: RepositorySnapshot,
    pub files: Vec<RepositoryFile>,
    pub exclusions: Vec<ExcludedPath>,
    pub detection: LanguageDetection,
}

/// Inspects an authorized local Git repository without executing repository code.
///
/// # Errors
/// Returns an error for a non-root/non-Git path, Git failure, unsafe filesystem
/// entries, symlinks, path escapes, or file I/O failures.
pub fn ingest_repository(
    authorized_root: impl AsRef<Path>,
    policy: &RepositoryPolicy,
) -> Result<RepositoryInventory, RepositoryError> {
    let root = dunce::canonicalize(authorized_root.as_ref()).map_err(RepositoryError::Io)?;
    if !root.is_dir() {
        return Err(RepositoryError::NotDirectory);
    }
    let git_root = PathBuf::from(git_text(&root, &["rev-parse", "--show-toplevel"])?);
    let git_root = dunce::canonicalize(git_root).map_err(RepositoryError::Io)?;
    if git_root != root {
        return Err(RepositoryError::NotRepositoryRoot {
            authorized: root,
            actual: git_root,
        });
    }
    let revision = git_text(&root, &["rev-parse", "--verify", "HEAD"])?;
    let dirty = !git_bytes(
        &root,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?
    .is_empty();

    let mut files = Vec::new();
    let mut exclusions = Vec::new();
    enumerate_directory(&root, &root, policy, &mut files, &mut exclusions)?;
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    exclusions.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let working_tree_hash = inventory_hash(&files);
    let paths = files
        .iter()
        .map(|file| file.relative_path.clone())
        .collect::<Vec<_>>();
    let detection = detect(&paths);

    Ok(RepositoryInventory {
        schema_version: SCHEMA_VERSION,
        snapshot: RepositorySnapshot::new(".", revision, working_tree_hash, dirty),
        files,
        exclusions,
        detection,
    })
}

fn enumerate_directory(
    root: &Path,
    directory: &Path,
    policy: &RepositoryPolicy,
    files: &mut Vec<RepositoryFile>,
    exclusions: &mut Vec<ExcludedPath>,
) -> Result<(), RepositoryError> {
    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| RepositoryError::PathEscape(path.clone()))?;
        let portable = portable_path(relative)?;
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(RepositoryError::Symlink(portable));
        }
        if metadata.is_dir() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(reason) = policy.excluded_directory(&name) {
                exclusions.push(ExcludedPath {
                    schema_version: SCHEMA_VERSION,
                    relative_path: portable,
                    reason,
                });
            } else {
                enumerate_directory(root, &path, policy, files, exclusions)?;
            }
        } else if metadata.is_file() {
            let resolved = resolve_repository_path(root, relative)?;
            if let Some(reason) = policy.excluded_file(relative, metadata.len(), &[]) {
                exclusions.push(ExcludedPath {
                    schema_version: SCHEMA_VERSION,
                    relative_path: portable,
                    reason,
                });
                continue;
            }
            let mut file = fs::File::open(&resolved)?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            let prefix_length = bytes.len().min(8 * 1024);
            if let Some(reason) =
                policy.excluded_file(relative, metadata.len(), &bytes[..prefix_length])
            {
                exclusions.push(ExcludedPath {
                    schema_version: SCHEMA_VERSION,
                    relative_path: portable,
                    reason,
                });
            } else {
                files.push(RepositoryFile {
                    schema_version: SCHEMA_VERSION,
                    relative_path: portable,
                    size_bytes: metadata.len(),
                    sha256: format!("{:x}", Sha256::digest(&bytes)),
                });
            }
        } else {
            exclusions.push(ExcludedPath {
                schema_version: SCHEMA_VERSION,
                relative_path: portable,
                reason: crate::ExclusionReason::UnsupportedFileType,
            });
        }
    }
    Ok(())
}

fn portable_path(path: &Path) -> Result<String, RepositoryError> {
    let components = path
        .components()
        .map(|component| {
            component
                .as_os_str()
                .to_str()
                .ok_or_else(|| RepositoryError::NonUnicodePath(path.to_path_buf()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(components.join("/"))
}

fn inventory_hash(files: &[RepositoryFile]) -> String {
    let mut hasher = Sha256::new();
    for file in files {
        hasher.update(file.relative_path.len().to_le_bytes());
        hasher.update(file.relative_path.as_bytes());
        hasher.update(file.size_bytes.to_le_bytes());
        hasher.update(file.sha256.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn git_text(root: &Path, arguments: &[&str]) -> Result<String, RepositoryError> {
    let bytes = git_bytes(root, arguments)?;
    let text = String::from_utf8(bytes).map_err(RepositoryError::GitUtf8)?;
    Ok(text.trim().to_owned())
}

fn git_bytes(root: &Path, arguments: &[&str]) -> Result<Vec<u8>, RepositoryError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .map_err(RepositoryError::GitSpawn)?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(RepositoryError::Git {
            arguments: arguments.join(" "),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        })
    }
}

#[derive(Debug, Error)]
pub enum RepositoryError {
    #[error("authorized repository path is not a directory")]
    NotDirectory,
    #[error(
        "authorized path must be the Git repository root; expected {authorized:?}, found {actual:?}"
    )]
    NotRepositoryRoot {
        authorized: PathBuf,
        actual: PathBuf,
    },
    #[error("symbolic link is forbidden during ingestion: {0}")]
    Symlink(String),
    #[error("path escaped the authorized repository: {0:?}")]
    PathEscape(PathBuf),
    #[error("repository path is not valid Unicode: {0:?}")]
    NonUnicodePath(PathBuf),
    #[error("filesystem I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("path policy rejected an entry: {0}")]
    PathPolicy(#[from] crate::PathPolicyError),
    #[error("could not execute Git: {0}")]
    GitSpawn(std::io::Error),
    #[error("Git output was not UTF-8: {0}")]
    GitUtf8(std::string::FromUtf8Error),
    #[error("Git command `{arguments}` failed: {stderr}")]
    Git { arguments: String, stderr: String },
}
