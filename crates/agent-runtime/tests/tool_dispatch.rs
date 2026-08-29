use std::fs;
use std::path::Path;
use std::process::Command;

use edsa_agent_runtime::roles::{AgentRole, ToolRequest, ToolResult, default_role_configurations};
use edsa_agent_runtime::{ToolDispatchError, ToolDispatcher};
use edsa_core::{RepositoryPolicy, ingest_repository};

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
