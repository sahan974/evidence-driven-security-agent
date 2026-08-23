use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredArtifact {
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug)]
pub struct ArtifactStore {
    root: PathBuf,
}

impl ArtifactStore {
    /// Opens or creates an artifact store below `root`.
    ///
    /// # Errors
    /// Returns an I/O error when the store cannot be created or resolved.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ArtifactError> {
        fs::create_dir_all(root.as_ref())?;
        let root = root.as_ref().canonicalize()?;
        fs::create_dir_all(root.join("sha256"))?;
        Ok(Self { root })
    }

    /// Stores bytes atomically under their SHA-256 digest.
    ///
    /// Existing objects are verified and never overwritten.
    ///
    /// # Errors
    /// Returns an error for I/O failures or if an existing object has drifted.
    pub fn put(&self, bytes: &[u8]) -> Result<StoredArtifact, ArtifactError> {
        let digest = sha256(bytes);
        let target = self.path_for_digest(&digest)?;
        let parent = target.parent().ok_or(ArtifactError::PathEscapesStore)?;
        fs::create_dir_all(parent)?;
        self.ensure_contained(parent)?;

        if target.exists() {
            let existing = fs::read(&target)?;
            if sha256(&existing) != digest || existing != bytes {
                return Err(ArtifactError::HashDrift(digest));
            }
        } else {
            let mut temporary = NamedTempFile::new_in(parent)?;
            temporary.write_all(bytes)?;
            temporary.as_file().sync_all()?;
            match temporary.persist_noclobber(&target) {
                Ok(_) => {}
                Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let existing = fs::read(&target)?;
                    if sha256(&existing) != digest || existing != bytes {
                        return Err(ArtifactError::HashDrift(digest));
                    }
                }
                Err(error) => return Err(ArtifactError::Io(error.error)),
            }
        }

        Ok(StoredArtifact {
            sha256: digest,
            size_bytes: u64::try_from(bytes.len()).map_err(|_| ArtifactError::SizeOverflow)?,
        })
    }

    /// Reads and verifies an artifact.
    ///
    /// # Errors
    /// Returns an error for invalid digests, missing objects, I/O, or hash drift.
    pub fn get(&self, digest: &str) -> Result<Vec<u8>, ArtifactError> {
        let target = self.path_for_digest(digest)?;
        let mut file = fs::File::open(target)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let actual = sha256(&bytes);
        if actual != digest {
            return Err(ArtifactError::HashDrift(digest.to_owned()));
        }
        Ok(bytes)
    }

    /// Resolves a validated digest to its internal object path.
    ///
    /// # Errors
    /// Returns an error unless `digest` is exactly 64 lowercase hexadecimal characters.
    pub fn path_for_digest(&self, digest: &str) -> Result<PathBuf, ArtifactError> {
        validate_digest(digest)?;
        let path = self.root.join("sha256").join(&digest[..2]).join(digest);
        if !path.starts_with(&self.root) {
            return Err(ArtifactError::PathEscapesStore);
        }
        Ok(path)
    }

    fn ensure_contained(&self, directory: &Path) -> Result<(), ArtifactError> {
        if !directory.canonicalize()?.starts_with(&self.root) {
            return Err(ArtifactError::PathEscapesStore);
        }
        Ok(())
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_digest(digest: &str) -> Result<(), ArtifactError> {
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ArtifactError::InvalidDigest(digest.to_owned()))
    }
}

#[derive(Debug, Error)]
pub enum ArtifactError {
    #[error("artifact digest is invalid: {0}")]
    InvalidDigest(String),
    #[error("artifact path escapes the configured store")]
    PathEscapesStore,
    #[error("artifact content no longer matches digest {0}")]
    HashDrift(String),
    #[error("artifact size cannot be represented")]
    SizeOverflow,
    #[error("artifact I/O failed: {0}")]
    Io(#[from] std::io::Error),
}
