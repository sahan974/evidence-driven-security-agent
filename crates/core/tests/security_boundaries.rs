use std::path::Path;

use edsa_core::{resolve_repository_path, validate_archive_entry};
use tempfile::tempdir;

#[test]
fn security_archive_traversal_is_rejected() {
    assert!(validate_archive_entry(Path::new("../../outside.txt")).is_err());
    assert!(validate_archive_entry(Path::new("safe/nested.txt")).is_ok());
}

#[test]
fn security_repository_symlink_is_rejected_when_supported() {
    let root = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let target = outside.path().join("secret.txt");
    std::fs::write(&target, "secret").unwrap();
    let link = root.path().join("link.txt");
    #[cfg(windows)]
    let created = std::os::windows::fs::symlink_file(&target, &link);
    #[cfg(unix)]
    let created = std::os::unix::fs::symlink(&target, &link);
    if created.is_ok() {
        assert!(resolve_repository_path(root.path(), Path::new("link.txt")).is_err());
    }
}
