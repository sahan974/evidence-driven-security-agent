use std::collections::BTreeSet;
use std::fs;

use edsa_cli::run_report;
use edsa_core::{
    DirtyTreeDecision, ProviderMetadata, RepositorySnapshot, RunApprovals, RunBudget,
    RunConfiguration, RunStatus,
};
use edsa_evidence::RunStore;

#[test]
fn terminal_run_gets_complete_verifiable_reports() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let run = temporary.path().join("run");
    let mut store = RunStore::create(&run, &configuration()).expect("run store");
    store
        .append_record(
            RunStatus::Cancelled,
            "cancelled by caller",
            serde_json::json!({
                "stage": "cancelled",
                "error": "requested cancellation"
            }),
        )
        .expect("terminal event");
    let manifest = run_report::finalize(&store).expect("final report");
    assert!(manifest.findings.is_empty());
    assert!(run.join("bundle/reports/results.json").is_file());
    assert!(run.join("bundle/reports/results.sarif").is_file());
    assert!(run.join("bundle/reports/replay.json").is_file());
    assert!(run.join("bundle/reports/run.json").is_file());
    assert!(run.join("bundle/reports/summary.md").is_file());
    assert_eq!(
        run_report::verify_run(&run).expect("verified aggregate"),
        manifest
    );
}

#[test]
fn changing_a_copied_prompt_record_breaks_run_verification() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let run = temporary.path().join("run");
    let mut store = RunStore::create(&run, &configuration()).expect("run store");
    store
        .append_record(
            RunStatus::Failed,
            "provider failed",
            serde_json::json!({
                "stage": "role_prompt",
                "prompt": "recorded prompt"
            }),
        )
        .expect("terminal event");
    run_report::finalize(&store).expect("final report");
    let ledger = run.join("bundle/events.jsonl");
    let contents = fs::read_to_string(&ledger).expect("bundle ledger");
    fs::write(
        &ledger,
        contents.replace("recorded prompt", "changed prompt"),
    )
    .expect("tamper bundle ledger");
    assert!(run_report::verify_run(&run).is_err());
}

fn configuration() -> RunConfiguration {
    RunConfiguration::new(
        RepositorySnapshot::new(".", "abc", "d".repeat(64), false),
        ProviderMetadata {
            provider: "openai-compatible".into(),
            model: "live-model".into(),
        },
        RunBudget {
            maximum_model_tokens: 1_000,
            maximum_cost_microusd: 1_000,
            maximum_turns: 10,
            maximum_experiments: 3,
            maximum_wall_time_seconds: 60,
        },
        RunApprovals::default(),
        DirtyTreeDecision::Clean,
        BTreeSet::new(),
        Vec::new(),
    )
}
