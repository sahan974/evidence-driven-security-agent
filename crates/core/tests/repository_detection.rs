use std::fs;
use std::path::Path;
use std::process::Command;

use edsa_core::{
    ExclusionReason, Language, ManifestKind, PathPolicyError, RepositoryError, RepositoryPolicy,
    ingest_repository, resolve_repository_path,
};
use tempfile::tempdir;

fn git(root: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .status()
        .unwrap();
    assert!(status.success(), "git command failed: {arguments:?}");
}

fn committed_repository() -> tempfile::TempDir {
    let directory = tempdir().unwrap();
    git(directory.path(), &["init", "-q"]);
    fs::write(directory.path().join("README.md"), "fixture\n").unwrap();
    git(directory.path(), &["add", "."]);
    git(
        directory.path(),
        &[
            "-c",
            "user.name=EDSA Tests",
            "-c",
            "user.email=edsa@example.invalid",
            "commit",
            "-q",
            "-m",
            "fixture",
        ],
    );
    directory
}

#[test]
fn repository_mixed_language_detection_is_stable() {
    let directory = committed_repository();
    fs::write(
        directory.path().join("pyproject.toml"),
        "[project]\nname='fixture'\n",
    )
    .unwrap();
    fs::write(directory.path().join("app.py"), "print('safe')\n").unwrap();
    fs::write(directory.path().join("package.json"), "{}\n").unwrap();
    fs::write(directory.path().join("tsconfig.json"), "{}\n").unwrap();
    fs::write(
        directory.path().join("index.ts"),
        "export const value = 1;\n",
    )
    .unwrap();
    fs::write(
        directory.path().join("go.mod"),
        "module example.invalid/fixture\n",
    )
    .unwrap();
    fs::write(directory.path().join("main.go"), "package main\n").unwrap();

    let first = ingest_repository(directory.path(), &RepositoryPolicy::default()).unwrap();
    let second = ingest_repository(directory.path(), &RepositoryPolicy::default()).unwrap();
    assert_eq!(first, second);
    assert!(first.snapshot.dirty);
    assert_eq!(
        first.detection.languages,
        [
            Language::Python,
            Language::TypeScript,
            Language::JavaScript,
            Language::Go
        ]
        .into_iter()
        .collect()
    );
    let kinds = first
        .detection
        .manifests
        .iter()
        .map(|manifest| manifest.kind)
        .collect::<Vec<_>>();
    assert!(kinds.contains(&ManifestKind::PythonProject));
    assert!(kinds.contains(&ManifestKind::NodePackage));
    assert!(kinds.contains(&ManifestKind::TypeScriptConfig));
    assert!(kinds.contains(&ManifestKind::GoModule));
}

#[test]
fn repository_dirty_content_changes_working_tree_hash() {
    let directory = committed_repository();
    fs::write(directory.path().join("app.py"), "value = 1\n").unwrap();
    let before = ingest_repository(directory.path(), &RepositoryPolicy::default()).unwrap();
    fs::write(directory.path().join("app.py"), "value = 2\n").unwrap();
    let after = ingest_repository(directory.path(), &RepositoryPolicy::default()).unwrap();
    assert_ne!(
        before.snapshot.content_digest,
        after.snapshot.content_digest
    );
    assert_eq!(before.snapshot.revision, after.snapshot.revision);
    assert!(after.snapshot.dirty);
}

#[test]
fn repository_exclusions_are_auditable() {
    let directory = committed_repository();
    fs::create_dir(directory.path().join("node_modules")).unwrap();
    fs::write(directory.path().join("node_modules/dep.js"), "ignored").unwrap();
    fs::create_dir(directory.path().join("dist")).unwrap();
    fs::write(directory.path().join("dist/bundle.js"), "generated").unwrap();
    fs::write(directory.path().join(".env"), "TOKEN=not-ingested").unwrap();
    fs::write(directory.path().join("image.png"), [0_u8, 1, 2]).unwrap();

    let inventory = ingest_repository(directory.path(), &RepositoryPolicy::default()).unwrap();
    let exclusions = inventory
        .exclusions
        .iter()
        .map(|item| (&item.relative_path, item.reason))
        .collect::<Vec<_>>();
    assert!(exclusions.contains(&(&"node_modules".to_owned(), ExclusionReason::Vendor)));
    assert!(exclusions.contains(&(&"dist".to_owned(), ExclusionReason::Generated)));
    assert!(exclusions.contains(&(&".env".to_owned(), ExclusionReason::SecretLike)));
    assert!(exclusions.contains(&(&"image.png".to_owned(), ExclusionReason::Binary)));
    assert!(
        !inventory
            .files
            .iter()
            .any(|file| file.relative_path == ".env")
    );
}

#[test]
fn repository_path_escape_is_rejected() {
    let directory = committed_repository();
    let result = resolve_repository_path(directory.path(), Path::new("../outside"));
    assert!(matches!(result, Err(PathPolicyError::Escape(_))));
}

#[test]
fn repository_subdirectory_is_not_accepted_as_authorized_root() {
    let directory = committed_repository();
    fs::create_dir(directory.path().join("nested")).unwrap();
    let result = ingest_repository(
        directory.path().join("nested"),
        &RepositoryPolicy::default(),
    );
    assert!(matches!(
        result,
        Err(RepositoryError::NotRepositoryRoot { .. })
    ));
}

#[test]
fn repository_ingestion_never_executes_declared_scripts() {
    let directory = committed_repository();
    let marker = directory.path().join("should-not-exist");
    fs::write(
        directory.path().join("package.json"),
        r#"{
  "scripts": {
    "prepare": "touch should-not-exist",
    "test": "touch should-not-exist"
  }
}"#,
    )
    .unwrap();

    let inventory = ingest_repository(directory.path(), &RepositoryPolicy::default()).unwrap();
    assert!(
        inventory
            .files
            .iter()
            .any(|file| file.relative_path == "package.json")
    );
    assert!(!marker.exists());
}

#[cfg(unix)]
#[test]
fn repository_symlink_is_rejected() {
    use std::os::unix::fs::symlink;

    let directory = committed_repository();
    fs::write(directory.path().join("outside.txt"), "outside").unwrap();
    symlink(
        directory.path().join("outside.txt"),
        directory.path().join("link.txt"),
    )
    .unwrap();
    let result = ingest_repository(directory.path(), &RepositoryPolicy::default());
    assert!(matches!(result, Err(RepositoryError::Symlink(_))));
}

#[cfg(windows)]
#[test]
fn repository_symlink_is_rejected_when_windows_allows_creation() {
    use std::os::windows::fs::symlink_file;

    let directory = committed_repository();
    fs::write(directory.path().join("outside.txt"), "outside").unwrap();
    let link = directory.path().join("link.txt");
    if symlink_file(directory.path().join("outside.txt"), &link).is_err() {
        return;
    }
    let result = ingest_repository(directory.path(), &RepositoryPolicy::default());
    assert!(matches!(result, Err(RepositoryError::Symlink(_))));
}
