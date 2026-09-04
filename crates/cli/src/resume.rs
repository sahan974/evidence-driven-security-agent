use std::collections::BTreeSet;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use edsa_agent_runtime::{LiveOrchestrator, RuntimeBudget, RuntimeError};
use edsa_core::{RepositoryPolicy, RunConfiguration, RunEvent, RunStatus, ingest_repository};
use edsa_evidence::RunStore;
use edsa_model_providers::ConfiguredProvider;
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::run_report;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResumeOutcome {
    pub run_id: String,
    pub output: PathBuf,
    pub status: RunStatus,
}

/// Continues an unfinished durable run from its newest verified checkpoints.
///
/// # Errors
/// Returns an error when the run ledger is invalid, the admitted repository or
/// provider changed, remaining work exceeds its budget, orchestration fails, or
/// the final report cannot be produced.
pub async fn execute(
    run_directory: &Path,
    cancellation: CancellationToken,
) -> Result<ResumeOutcome, ResumeError> {
    let mut store = RunStore::open(run_directory)?;
    let configuration = store.configuration()?;
    if store.current_status()?.is_some_and(RunStatus::is_terminal) {
        run_report::finalize(&store)?;
        return outcome(&store, &configuration);
    }
    let current_directory = env::current_dir()?;
    let repository_path = absolute(
        &current_directory,
        Path::new(&configuration.repository.repository_path),
    )?;
    let ingestion_path = repository_path.clone();
    let mut inventory = tokio::task::spawn_blocking(move || {
        ingest_repository(ingestion_path, &RepositoryPolicy::default())
    })
    .await
    .map_err(|error| ResumeError::IngestionTask(error.to_string()))??;
    inventory.snapshot.repository_path = repository_path.to_string_lossy().into_owned();
    if inventory.snapshot.revision != configuration.repository.revision
        || inventory.snapshot.content_digest != configuration.repository.content_digest
        || inventory.snapshot.dirty != configuration.repository.dirty
    {
        return Err(ResumeError::RepositoryChanged);
    }
    let provider = Arc::new(ConfiguredProvider::from_environment()?);
    if provider.model() != configuration.provider.model {
        return Err(ResumeError::ProviderChanged {
            expected: configuration.provider.model,
            actual: provider.model().to_owned(),
        });
    }
    let budget = remaining_budget(&configuration, &store.events()?);
    let orchestrator = LiveOrchestrator::new(
        provider,
        configuration.provider.model.clone(),
        budget,
        repository_path,
        &inventory,
    );
    if let Err(error) = orchestrator
        .run(&inventory, &mut store, &cancellation)
        .await
    {
        if cancellation.is_cancelled()
            || matches!(
                error,
                edsa_agent_runtime::OrchestrationError::Runtime(RuntimeError::Cancelled)
            )
        {
            store.append_record(
                RunStatus::Running,
                "resumed orchestration paused; unfinished work remains durable",
                serde_json::json!({ "stage": "resume_paused" }),
            )?;
            return Err(ResumeError::Orchestration(error));
        }
        let status = match &error {
            edsa_agent_runtime::OrchestrationError::Runtime(RuntimeError::Budget(
                edsa_agent_runtime::RuntimeEvent::BudgetExhausted {
                    dimension: edsa_agent_runtime::BudgetDimension::WallTime,
                    ..
                },
            )) => RunStatus::TimedOut,
            edsa_agent_runtime::OrchestrationError::Runtime(RuntimeError::Budget(_)) => {
                RunStatus::Inconclusive
            }
            _ => RunStatus::Failed,
        };
        store.append_record(
            status,
            "resumed orchestration terminated",
            serde_json::json!({
                "stage": "resume_terminated",
                "error": error.to_string()
            }),
        )?;
        run_report::finalize(&store)?;
        return Err(ResumeError::Orchestration(error));
    }
    run_report::finalize(&store)?;
    outcome(&store, &configuration)
}

fn remaining_budget(configuration: &RunConfiguration, events: &[RunEvent]) -> RuntimeBudget {
    let mut checkpoints = BTreeSet::new();
    let mut turns = 0_u64;
    let mut tokens = 0_u64;
    let mut cost = 0_u64;
    let mut experiments = 0_u32;
    for event in events {
        let Some(key) = event.payload.get("checkpoint_key").and_then(Value::as_str) else {
            continue;
        };
        if !checkpoints.insert(key.to_owned()) {
            continue;
        }
        if key.starts_with("role:") {
            turns = turns.saturating_add(1);
            if key.starts_with("role:experiment_designer:") {
                experiments = experiments.saturating_add(1);
            }
            tokens = tokens.saturating_add(
                event
                    .payload
                    .pointer("/checkpoint/usage/total_tokens")
                    .and_then(Value::as_u64)
                    .unwrap_or_default(),
            );
            cost = cost.saturating_add(
                event
                    .payload
                    .pointer("/checkpoint/estimated_cost_microusd")
                    .and_then(Value::as_u64)
                    .unwrap_or_default(),
            );
        }
    }
    RuntimeBudget {
        maximum_turns: u64::from(configuration.budget.maximum_turns).saturating_sub(turns),
        // Paused wall-clock time is not execution time. Each resumed process gets
        // the configured active-execution window while durable token, cost, turn,
        // and experiment consumption remains deducted.
        maximum_wall_time_seconds: configuration.budget.maximum_wall_time_seconds,
        maximum_model_tokens: configuration
            .budget
            .maximum_model_tokens
            .saturating_sub(tokens),
        maximum_cost_microusd: configuration
            .budget
            .maximum_cost_microusd
            .saturating_sub(cost),
        maximum_experiments: configuration
            .budget
            .maximum_experiments
            .saturating_sub(experiments),
        maximum_concurrency: 1,
    }
}

fn outcome(
    store: &RunStore,
    configuration: &RunConfiguration,
) -> Result<ResumeOutcome, ResumeError> {
    Ok(ResumeOutcome {
        run_id: configuration.run_id.as_str().to_owned(),
        output: store.root().to_path_buf(),
        status: store.current_status()?.unwrap_or(RunStatus::Failed),
    })
}

fn absolute(current_directory: &Path, path: &Path) -> Result<PathBuf, std::io::Error> {
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        current_directory.join(path)
    };
    std::path::absolute(candidate)
}

#[derive(Debug, Error)]
pub enum ResumeError {
    #[error("run storage failed: {0}")]
    Store(#[from] edsa_evidence::RunStoreError),
    #[error("repository ingestion failed: {0}")]
    Repository(#[from] edsa_core::RepositoryError),
    #[error("repository ingestion task failed: {0}")]
    IngestionTask(String),
    #[error("the admitted repository changed after the run was created")]
    RepositoryChanged,
    #[error("configured model changed: expected {expected}, found {actual}")]
    ProviderChanged { expected: String, actual: String },
    #[error("provider configuration failed: {0}")]
    Provider(#[from] edsa_model_providers::ProviderError),
    #[error("resumed orchestration failed: {0}")]
    Orchestration(#[from] edsa_agent_runtime::OrchestrationError),
    #[error("run report failed: {0}")]
    Report(#[from] crate::run_report::RunReportError),
    #[error("path resolution failed: {0}")]
    Io(#[from] std::io::Error),
}
