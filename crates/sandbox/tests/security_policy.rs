use std::collections::BTreeMap;
use std::time::Duration;

use edsa_sandbox::{
    CommandExecutor, CommandSpec, PolicyDecision, ProcessCommandExecutor, SandboxPolicy,
};
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;

#[test]
fn security_network_and_dependency_installation_need_separate_approvals() {
    let root = tempdir().unwrap();
    let environment = BTreeMap::new();
    let network = SandboxPolicy {
        network_enabled: true,
        ..SandboxPolicy::default()
    };
    assert!(
        network
            .validate(root.path(), "image", &["test".into()], &environment)
            .is_err()
    );

    let dependency = SandboxPolicy::default();
    assert!(
        dependency
            .validate(
                root.path(),
                "image",
                &["npm".into(), "install".into()],
                &environment
            )
            .is_err()
    );
    assert!(
        dependency
            .validate(
                root.path(),
                "image",
                &["sh".into(), "-c".into(), "npm install".into()],
                &environment
            )
            .is_err()
    );

    let approved = SandboxPolicy {
        network_enabled: true,
        network_decision: PolicyDecision::Approved,
        dependency_installation_decision: PolicyDecision::Approved,
        ..SandboxPolicy::default()
    };
    assert!(
        approved
            .validate(
                root.path(),
                "image",
                &["npm".into(), "install".into()],
                &environment
            )
            .is_ok()
    );
}

#[test]
fn security_secret_environment_is_denied_even_when_allowlisted() {
    let root = tempdir().unwrap();
    let mut policy = SandboxPolicy::default();
    policy.allowed_environment.insert("MODEL_API_KEY".into());
    let environment = BTreeMap::from([("MODEL_API_KEY".into(), "secret".into())]);
    assert!(
        policy
            .validate(root.path(), "image", &["test".into()], &environment)
            .is_err()
    );
}

#[tokio::test]
async fn security_output_flooding_is_bounded_and_marked_truncated() {
    let output = ProcessCommandExecutor
        .execute(CommandSpec {
            program: "powershell".into(),
            arguments: vec![
                "-NoProfile".into(),
                "-Command".into(),
                "[Console]::Out.Write('x' * 10000)".into(),
            ],
            timeout: Duration::from_secs(5),
            maximum_output_bytes_per_stream: 64,
            cancellation: CancellationToken::new(),
        })
        .await
        .unwrap();
    assert_eq!(output.stdout.len(), 64);
    assert!(output.stdout_truncated);
}
