use std::env;
use std::path::PathBuf;

use edsa_cli::patch::{PatchArguments, execute};
use edsa_core::PatchAttemptStatus;
use tokio_util::sync::CancellationToken;

#[tokio::test]
#[ignore = "requires a completed TypeScript live run, hosted model key, and Docker"]
async fn live_typescript_patch_passes_every_gate() {
    verify_language("TYPESCRIPT").await;
}

#[tokio::test]
#[ignore = "requires a completed Go live run, hosted model key, and Docker"]
async fn live_go_patch_passes_every_gate() {
    verify_language("GO").await;
}

#[tokio::test]
#[ignore = "requires three completed live runs, a hosted model key, Docker, and runtime images"]
async fn live_python_typescript_and_go_patches_pass_every_gate() {
    for language in ["PYTHON", "TYPESCRIPT", "GO"] {
        verify_language(language).await;
    }
}

async fn verify_language(language: &str) {
    let run = env::var(format!("EDSA_PATCH_{language}_RUN"))
        .unwrap_or_else(|_| panic!("EDSA_PATCH_{language}_RUN is required"));
    let finding_id = env::var(format!("EDSA_PATCH_{language}_FINDING"))
        .unwrap_or_else(|_| panic!("EDSA_PATCH_{language}_FINDING is required"));
    let outcome = execute(
        PatchArguments {
            run_directory: PathBuf::from(run),
            finding_id,
            approved: true,
            maximum_attempts: 2,
        },
        CancellationToken::new(),
    )
    .await
    .unwrap_or_else(|error| panic!("{language} live patch failed: {error}"));
    assert_eq!(outcome.status, PatchAttemptStatus::Verified);
    assert_eq!(
        outcome.original_before_sha256,
        outcome.original_after_sha256
    );
    assert!(
        outcome
            .attempts
            .last()
            .is_some_and(|attempt| attempt.verification.all_required_gates_pass())
    );
}
