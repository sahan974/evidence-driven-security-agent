use std::fs;
use std::path::Path;
use std::process::Command;

use edsa_agent_runtime::roles::{
    AgentRole, ToolCapability, ToolRequest, ToolResult, default_role_configurations,
};
use edsa_agent_runtime::{ToolDispatchError, ToolDispatcher};
use edsa_core::{RepositoryPolicy, ingest_repository};
use edsa_evidence::{ArtifactError, ArtifactStore};

fn git(repository: &Path, arguments: &[&str]) {
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(arguments)
            .status()
            .expect("git should start")
            .success()
    );
}

#[test]
fn role_permissions_and_repository_boundaries_are_enforced() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let repository = temporary.path().join("repository");
    fs::create_dir(&repository).expect("repository directory");
    fs::write(repository.join("app.py"), "print('needle')\n").expect("source");
    git(&repository, &["init"]);
    git(
        &repository,
        &["config", "user.email", "tests@example.invalid"],
    );
    git(&repository, &["config", "user.name", "EDSA Tests"]);
    git(&repository, &["add", "app.py"]);
    git(&repository, &["commit", "-m", "fixture"]);
    let inventory = ingest_repository(&repository, &RepositoryPolicy::default()).expect("ingest");
    let dispatcher = ToolDispatcher::new(&repository, &inventory, default_role_configurations());

    let read = ToolRequest::ReadRepositoryFile {
        relative_path: "app.py".into(),
        start_byte: 0,
        maximum_bytes: 1024,
    };
    assert!(matches!(
        dispatcher.dispatch(AgentRole::Mapper, &read),
        Ok(ToolResult::RepositoryFile { .. })
    ));
    assert!(matches!(
        dispatcher.dispatch(AgentRole::EvidenceCritic, &read),
        Err(ToolDispatchError::Forbidden { .. })
    ));

    let escape = ToolRequest::ReadRepositoryFile {
        relative_path: "../outside.txt".into(),
        start_byte: 0,
        maximum_bytes: 1024,
    };
    assert!(matches!(
        dispatcher.dispatch(AgentRole::Mapper, &escape),
        Err(ToolDispatchError::UnadmittedPath(_))
    ));
}

#[test]
fn evidence_artifacts_are_hash_verified_before_bounded_delivery() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let repository = temporary.path().join("repository");
    fs::create_dir(&repository).expect("repository directory");
    fs::write(repository.join("app.py"), "print('needle')\n").expect("source");
    git(&repository, &["init"]);
    git(
        &repository,
        &["config", "user.email", "tests@example.invalid"],
    );
    git(&repository, &["config", "user.name", "EDSA Tests"]);
    git(&repository, &["add", "app.py"]);
    git(&repository, &["commit", "-m", "fixture"]);
    let inventory = ingest_repository(&repository, &RepositoryPolicy::default()).expect("ingest");
    let dispatcher = ToolDispatcher::new(&repository, &inventory, default_role_configurations());
    let artifacts =
        ArtifactStore::open(temporary.path().join("artifacts")).expect("artifact store");
    let stored = artifacts
        .put(b"verified experiment evidence")
        .expect("store artifact");
    let request = ToolRequest::ReadEvidenceArtifact {
        sha256: stored.sha256.clone(),
        maximum_bytes: 8,
    };

    assert_eq!(
        dispatcher
            .dispatch_with_evidence(AgentRole::EvidenceCritic, &request, &artifacts)
            .expect("read verified artifact"),
        ToolResult::EvidenceArtifact {
            sha256: stored.sha256.clone(),
            media_type: "application/octet-stream".into(),
            content: b"verified".to_vec(),
            truncated: true,
        }
    );

    let artifact_path = artifacts
        .path_for_digest(&stored.sha256)
        .expect("artifact path");
    fs::write(artifact_path, b"tampered experiment evidence").expect("tamper artifact");
    assert!(matches!(
        dispatcher.dispatch_with_evidence(AgentRole::EvidenceCritic, &request, &artifacts),
        Err(ToolDispatchError::Artifact(ArtifactError::HashDrift(_)))
    ));
}

#[test]
fn evidence_reads_reject_invalid_digests_and_excessive_limits() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let repository = temporary.path().join("repository");
    fs::create_dir(&repository).expect("repository directory");
    fs::write(repository.join("app.py"), "pass\n").expect("source");
    git(&repository, &["init"]);
    git(
        &repository,
        &["config", "user.email", "tests@example.invalid"],
    );
    git(&repository, &["config", "user.name", "EDSA Tests"]);
    git(&repository, &["add", "app.py"]);
    git(&repository, &["commit", "-m", "fixture"]);
    let inventory = ingest_repository(&repository, &RepositoryPolicy::default()).expect("ingest");
    let dispatcher = ToolDispatcher::new(&repository, &inventory, default_role_configurations());
    let artifacts =
        ArtifactStore::open(temporary.path().join("artifacts")).expect("artifact store");

    let invalid_digest = ToolRequest::ReadEvidenceArtifact {
        sha256: "../not-a-digest".into(),
        maximum_bytes: 1,
    };
    assert!(matches!(
        dispatcher.dispatch_with_evidence(AgentRole::EvidenceCritic, &invalid_digest, &artifacts),
        Err(ToolDispatchError::Artifact(ArtifactError::InvalidDigest(_)))
    ));

    let excessive = ToolRequest::ReadEvidenceArtifact {
        sha256: "0".repeat(64),
        maximum_bytes: 64 * 1024 + 1,
    };
    assert!(matches!(
        dispatcher.dispatch_with_evidence(AgentRole::EvidenceCritic, &excessive, &artifacts),
        Err(ToolDispatchError::ArtifactReadLimit(_))
    ));
}

#[test]
fn unimplemented_or_unsafe_mutating_tools_are_not_advertised() {
    let configurations = default_role_configurations();
    assert!(
        !configurations
            .get(&AgentRole::Reviewer)
            .expect("reviewer")
            .allowed_tools
            .contains(&ToolCapability::RunSandboxExperiment)
    );
    assert!(
        !configurations
            .get(&AgentRole::PatchAgent)
            .expect("patch agent")
            .allowed_tools
            .contains(&ToolCapability::ProposePatch)
    );
}
