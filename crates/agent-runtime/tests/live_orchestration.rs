use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use edsa_agent_runtime::{AgentRole, LiveOrchestrator, RuntimeBudget};
use edsa_core::{
    DirtyTreeDecision, ProviderMetadata, RepositoryPolicy, RunApprovals, RunBudget,
    RunConfiguration, RunStatus, ingest_repository,
};
use edsa_evidence::RunStore;
use edsa_model_providers::ConfiguredProvider;
use tokio_util::sync::CancellationToken;

fn git(repository: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .env_remove("MODEL_API_KEY")
        .env_remove("OPENROUTER_API_KEY")
        .status()
        .expect("git should start");
    assert!(status.success(), "git failed: {arguments:?}");
}

#[tokio::test]
#[ignore = "requires configured MODEL_* credentials and incurs live provider cost"]
async fn configured_provider_runs_all_required_roles_on_adversarial_repository() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let repository = temporary.path().join("repository");
    fs::create_dir(&repository).expect("repository directory");
    fs::write(
        repository.join("app.py"),
        include_str!("fixtures/adversarial_python/app.py"),
    )
    .expect("fixture source");
    git(&repository, &["init"]);
    git(
        &repository,
        &["config", "user.email", "tests@example.invalid"],
    );
    git(&repository, &["config", "user.name", "EDSA Live Test"]);
    git(&repository, &["add", "app.py"]);
    git(&repository, &["commit", "-m", "adversarial fixture"]);

    let inventory =
        ingest_repository(&repository, &RepositoryPolicy::default()).expect("repository admission");
    let provider = Arc::new(ConfiguredProvider::from_environment().expect("live provider"));
    let model = provider.model().to_owned();
    let budget = RunBudget {
        maximum_model_tokens: 60_000,
        maximum_cost_microusd: 250_000,
        maximum_turns: 8,
        maximum_experiments: 2,
        maximum_wall_time_seconds: 300,
    };
    let configuration = RunConfiguration::new(
        inventory.snapshot.clone(),
        ProviderMetadata {
            provider: "openai-compatible".into(),
            model: model.clone(),
        },
        budget.clone(),
        RunApprovals::default(),
        DirtyTreeDecision::Clean,
        inventory.detection.languages.clone(),
        Vec::new(),
    );
    let output = temporary.path().join("evidence");
    let mut store = RunStore::create(&output, &configuration).expect("run store");
    store
        .append_event(RunStatus::Ready, "provider admitted")
        .expect("ready event");
    let orchestrator = LiveOrchestrator::new(
        provider,
        model,
        RuntimeBudget {
            maximum_turns: u64::from(budget.maximum_turns),
            maximum_wall_time_seconds: budget.maximum_wall_time_seconds,
            maximum_model_tokens: budget.maximum_model_tokens,
            maximum_cost_microusd: budget.maximum_cost_microusd,
            maximum_experiments: budget.maximum_experiments,
            maximum_concurrency: 1,
        },
        &repository,
        &inventory,
    );
    let summary = orchestrator
        .run(&inventory, &mut store, &CancellationToken::new())
        .await
        .expect("live orchestration");
    let required = BTreeSet::from([
        AgentRole::Mapper,
        AgentRole::HypothesisPlanner,
        AgentRole::ExperimentDesigner,
        AgentRole::EvidenceCritic,
        AgentRole::Reviewer,
    ]);
    assert!(required.is_subset(&summary.roles_completed));
    assert!(summary.usage.model_tokens > 0);
    assert!(summary.usage.model_tokens <= budget.maximum_model_tokens);
    assert!(summary.usage.cost_microusd <= budget.maximum_cost_microusd);
    assert_eq!(
        store.current_status().expect("status"),
        Some(RunStatus::Inconclusive)
    );

    let event_text = fs::read_to_string(output.join("events.jsonl")).expect("event stream");
    let events = event_text
        .lines()
        .map(|line| serde_json::from_str::<edsa_core::RunEvent>(line).expect("valid event"))
        .collect::<Vec<_>>();
    assert!(
        events
            .iter()
            .all(|event| event.status != RunStatus::Completed)
    );
    assert!(
        events
            .iter()
            .all(|event| event.payload.get("verdict").is_none())
    );
    if let Ok(key) = std::env::var("MODEL_API_KEY") {
        assert!(!event_text.contains(&key));
    }
}
