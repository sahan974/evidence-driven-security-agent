use std::collections::BTreeSet;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use edsa_agent_runtime::{LiveOrchestrator, RuntimeBudget, RuntimeError};
use edsa_core::{
    Approval, DirtyTreeDecision, OptionalTool, ProviderMetadata, RepositoryPolicy, RunApprovals,
    RunBudget, RunConfiguration, RunStatus, ingest_repository,
};
use edsa_evidence::RunStore;
use edsa_model_providers::ConfiguredProvider;
use serde::Serialize;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::run_report;

const OPTIONAL_TOOLS: &[(&str, &str)] = &[("semgrep", "semgrep"), ("codeql", "codeql")];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanArguments {
    pub repository: PathBuf,
    pub output: PathBuf,
    pub budget: RunBudget,
    pub approvals: RunApprovals,
    pub optional_tools: BTreeSet<String>,
    pub admit_only: bool,
    pub propose_patches: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ScanOutcome {
    pub run_id: String,
    pub output: PathBuf,
    pub status: RunStatus,
}

#[must_use]
pub fn usage() -> &'static str {
    "usage: edsa scan <repository> --output <directory> --max-tokens <count> \
--max-cost-microusd <amount> --max-turns <count> --max-experiments <count> \
--timeout-seconds <count> [--allow-dirty] [--allow-network] \
[--allow-dependency-installation] [--allow-patch-application] \
[--enable-tool semgrep|codeql] [--propose-patches] [--admit-only]"
}

/// Parses and validates scan command arguments without touching the repository.
///
/// # Errors
/// Returns an error for missing, unknown, duplicate, or invalid options.
pub fn parse(arguments: Vec<String>) -> Result<ScanArguments, ScanError> {
    let mut arguments = arguments.into_iter();
    let repository = arguments.next().ok_or(ScanError::Usage)?.into();
    let mut output = None;
    let mut maximum_model_tokens = None;
    let mut maximum_cost_microusd = None;
    let mut maximum_turns = None;
    let mut maximum_experiments = None;
    let mut maximum_wall_time_seconds = None;
    let mut approvals = RunApprovals::default();
    let mut optional_tools = BTreeSet::new();
    let mut admit_only = false;
    let mut propose_patches = false;

    while let Some(option) = arguments.next() {
        match option.as_str() {
            "--output" => set_once(&mut output, path_value(&mut arguments, &option)?, &option)?,
            "--max-tokens" => set_once(
                &mut maximum_model_tokens,
                integer_value(&mut arguments, &option)?,
                &option,
            )?,
            "--max-cost-microusd" => set_once(
                &mut maximum_cost_microusd,
                integer_value(&mut arguments, &option)?,
                &option,
            )?,
            "--max-turns" => set_once(
                &mut maximum_turns,
                integer_value(&mut arguments, &option)?,
                &option,
            )?,
            "--max-experiments" => set_once(
                &mut maximum_experiments,
                integer_value(&mut arguments, &option)?,
                &option,
            )?,
            "--timeout-seconds" => set_once(
                &mut maximum_wall_time_seconds,
                integer_value(&mut arguments, &option)?,
                &option,
            )?,
            "--allow-dirty" => grant(&mut approvals, Approval::DirtyRepository, &option)?,
            "--allow-network" => grant(&mut approvals, Approval::Network, &option)?,
            "--allow-dependency-installation" => {
                grant(&mut approvals, Approval::DependencyInstallation, &option)?;
            }
            "--allow-patch-application" => {
                grant(&mut approvals, Approval::PatchApplication, &option)?;
            }
            "--enable-tool" => {
                let tool = arguments
                    .next()
                    .ok_or_else(|| ScanError::MissingValue(option.clone()))?;
                if !OPTIONAL_TOOLS.iter().any(|(name, _)| *name == tool) {
                    return Err(ScanError::UnsupportedTool(tool));
                }
                if !optional_tools.insert(tool.clone()) {
                    return Err(ScanError::DuplicateOption(format!("--enable-tool {tool}")));
                }
            }
            "--admit-only" => set_boolean(&mut admit_only, &option)?,
            "--propose-patches" => set_boolean(&mut propose_patches, &option)?,
            _ => return Err(ScanError::UnknownOption(option)),
        }
    }

    let budget = RunBudget {
        maximum_model_tokens: required(maximum_model_tokens, "--max-tokens")?,
        maximum_cost_microusd: required(maximum_cost_microusd, "--max-cost-microusd")?,
        maximum_turns: required(maximum_turns, "--max-turns")?,
        maximum_experiments: required(maximum_experiments, "--max-experiments")?,
        maximum_wall_time_seconds: required(maximum_wall_time_seconds, "--timeout-seconds")?,
    };
    if !budget.is_valid() {
        return Err(ScanError::InvalidBudget);
    }
    Ok(ScanArguments {
        repository,
        output: required(output, "--output")?,
        budget,
        approvals,
        optional_tools,
        admit_only,
        propose_patches,
    })
}

/// Admits a repository and creates the durable run that Task 18 can continue.
///
/// This function validates all configuration before creating the output directory.
/// It does not make a model request or execute repository code.
///
/// # Errors
/// Returns an error for invalid provider configuration, repository policy, tools, or storage.
pub async fn execute(
    arguments: ScanArguments,
    cancellation: CancellationToken,
) -> Result<ScanOutcome, ScanError> {
    if arguments.propose_patches && !arguments.approvals.contains(Approval::PatchApplication) {
        return Err(ScanError::PatchApprovalRequired);
    }
    if arguments.propose_patches && arguments.admit_only {
        return Err(ScanError::PatchProposalRequiresLiveScan);
    }
    let propose_patches = arguments.propose_patches;
    let provider = Arc::new(ConfiguredProvider::from_environment()?);
    let provider_metadata = ProviderMetadata {
        provider: env::var("MODEL_PROVIDER").unwrap_or_else(|_| "openai-compatible".into()),
        model: provider.model().to_owned(),
    };
    let admit_only = arguments.admit_only;
    let budget = arguments.budget.clone();
    let model = provider.model().to_owned();
    let mut prepared =
        prepare_with_admitted_provider(arguments, cancellation.clone(), provider_metadata).await?;
    if prepared.outcome.status != RunStatus::Ready {
        run_report::finalize(&prepared.store)?;
        return Ok(prepared.outcome);
    }
    if admit_only {
        return Ok(prepared.outcome);
    }
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
        prepared.repository_path.clone(),
        &prepared.inventory,
    );
    match orchestrator
        .run(&prepared.inventory, &mut prepared.store, &cancellation)
        .await
    {
        Ok(_) => {
            prepared.outcome.status = prepared
                .store
                .current_status()?
                .unwrap_or(RunStatus::Failed);
            let manifest = run_report::finalize(&prepared.store)?;
            propose_confirmed_patches(
                propose_patches,
                &manifest,
                &prepared.outcome.output,
                &cancellation,
            )
            .await?;
            Ok(prepared.outcome)
        }
        Err(error) => {
            if cancellation.is_cancelled()
                || matches!(
                    error,
                    edsa_agent_runtime::OrchestrationError::Runtime(RuntimeError::Cancelled)
                )
            {
                prepared.store.append_record(
                    RunStatus::Running,
                    "live orchestration paused; resume can continue unfinished work",
                    serde_json::json!({ "stage": "orchestration_paused" }),
                )?;
                return Err(ScanError::Orchestration(error));
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
            prepared.store.append_record(
                status,
                "live orchestration terminated",
                serde_json::json!({
                    "stage": "orchestration_terminated",
                    "error": error.to_string()
                }),
            )?;
            run_report::finalize(&prepared.store)?;
            Err(ScanError::Orchestration(error))
        }
    }
}

async fn propose_confirmed_patches(
    enabled: bool,
    manifest: &edsa_reporting::EvidenceBundleManifest,
    run_directory: &Path,
    cancellation: &CancellationToken,
) -> Result<(), ScanError> {
    if !enabled {
        return Ok(());
    }
    for finding in manifest
        .findings
        .iter()
        .filter(|finding| finding.verdict == edsa_core::Verdict::Confirmed)
    {
        crate::patch::execute(
            crate::patch::PatchArguments {
                run_directory: run_directory.to_path_buf(),
                finding_id: finding.id.clone(),
                approved: true,
                maximum_attempts: 2,
            },
            cancellation.clone(),
        )
        .await?;
    }
    Ok(())
}

#[cfg(test)]
async fn execute_with_admitted_provider(
    arguments: ScanArguments,
    cancellation: CancellationToken,
    provider_metadata: ProviderMetadata,
) -> Result<ScanOutcome, ScanError> {
    prepare_with_admitted_provider(arguments, cancellation, provider_metadata)
        .await
        .map(|prepared| prepared.outcome)
}

#[derive(Debug)]
struct PreparedRun {
    outcome: ScanOutcome,
    store: RunStore,
    inventory: edsa_core::RepositoryInventory,
    repository_path: PathBuf,
}

async fn prepare_with_admitted_provider(
    arguments: ScanArguments,
    cancellation: CancellationToken,
    provider_metadata: ProviderMetadata,
) -> Result<PreparedRun, ScanError> {
    let started = Instant::now();
    let current_directory = env::current_dir()?;
    let repository_path = absolute(&current_directory, &arguments.repository)?;
    let output = absolute(&current_directory, &arguments.output)?;
    if output.exists() {
        return Err(ScanError::OutputCollision(output));
    }
    if output == repository_path || output.starts_with(&repository_path) {
        return Err(ScanError::UnsafeOutput(output));
    }
    let enabled_optional_tools = resolve_tools(&arguments.optional_tools)?;

    let ingestion_path = repository_path.clone();
    let mut inventory = tokio::task::spawn_blocking(move || {
        ingest_repository(ingestion_path, &RepositoryPolicy::default())
    })
    .await
    .map_err(|error| ScanError::IngestionTask(error.to_string()))??;
    inventory.snapshot.repository_path = repository_path.to_string_lossy().into_owned();
    if inventory.detection.languages.is_empty() {
        return Err(ScanError::UnsupportedRepository);
    }
    let dirty_tree_decision = if inventory.snapshot.dirty {
        if !arguments.approvals.contains(Approval::DirtyRepository) {
            return Err(ScanError::DirtyRepository);
        }
        DirtyTreeDecision::ExplicitlyAllowed
    } else {
        DirtyTreeDecision::Clean
    };

    let timeout = Duration::from_secs(arguments.budget.maximum_wall_time_seconds);
    let configuration = RunConfiguration::new(
        inventory.snapshot.clone(),
        provider_metadata,
        arguments.budget,
        arguments.approvals,
        dirty_tree_decision,
        inventory.detection.languages.clone(),
        enabled_optional_tools,
    );
    let mut store = RunStore::create(&output, &configuration)?;
    let status = if cancellation.is_cancelled() {
        store.append_event(RunStatus::Cancelled, "scan cancelled after admission")?;
        RunStatus::Cancelled
    } else if started.elapsed() >= timeout {
        store.append_event(
            RunStatus::TimedOut,
            "scan admission exceeded the configured wall-time budget",
        )?;
        RunStatus::TimedOut
    } else {
        store.append_event(
            RunStatus::Ready,
            "provider admitted; run is ready for live agent orchestration",
        )?;
        RunStatus::Ready
    };
    Ok(PreparedRun {
        outcome: ScanOutcome {
            run_id: configuration.run_id.as_str().to_owned(),
            output: store.root().to_path_buf(),
            status,
        },
        store,
        inventory,
        repository_path,
    })
}

fn absolute(current_directory: &Path, path: &Path) -> Result<PathBuf, ScanError> {
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        current_directory.join(path)
    };
    std::path::absolute(candidate).map_err(Into::into)
}

fn resolve_tools(requested: &BTreeSet<String>) -> Result<Vec<OptionalTool>, ScanError> {
    requested
        .iter()
        .map(|name| {
            let executable = OPTIONAL_TOOLS
                .iter()
                .find_map(|(known, executable)| (*known == name).then_some(*executable))
                .ok_or_else(|| ScanError::UnsupportedTool(name.clone()))?;
            let path = executable_path(executable)
                .ok_or_else(|| ScanError::ToolUnavailable(name.clone()))?;
            Ok(OptionalTool {
                name: name.clone(),
                executable: path.to_string_lossy().into_owned(),
            })
        })
        .collect()
}

fn executable_path(name: &str) -> Option<PathBuf> {
    let paths = env::var_os("PATH")?;
    let extensions = env::var_os("PATHEXT").map_or_else(
        || vec![String::new()],
        |value| {
            value
                .to_string_lossy()
                .split(';')
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        },
    );
    for directory in env::split_paths(&paths) {
        for extension in &extensions {
            let candidate = directory.join(format!("{name}{extension}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn integer_value<T>(
    arguments: &mut impl Iterator<Item = String>,
    option: &str,
) -> Result<T, ScanError>
where
    T: std::str::FromStr,
{
    arguments
        .next()
        .ok_or_else(|| ScanError::MissingValue(option.to_owned()))?
        .parse()
        .map_err(|_| ScanError::InvalidInteger(option.to_owned()))
}

fn path_value(
    arguments: &mut impl Iterator<Item = String>,
    option: &str,
) -> Result<PathBuf, ScanError> {
    arguments
        .next()
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| ScanError::MissingValue(option.to_owned()))
}

fn required<T>(value: Option<T>, option: &'static str) -> Result<T, ScanError> {
    value.ok_or(ScanError::MissingOption(option))
}

fn set_once<T>(slot: &mut Option<T>, value: T, option: &str) -> Result<(), ScanError> {
    if slot.replace(value).is_some() {
        Err(ScanError::DuplicateOption(option.to_owned()))
    } else {
        Ok(())
    }
}

fn grant(approvals: &mut RunApprovals, approval: Approval, option: &str) -> Result<(), ScanError> {
    if approvals.grant(approval) {
        Ok(())
    } else {
        Err(ScanError::DuplicateOption(option.to_owned()))
    }
}

fn set_boolean(value: &mut bool, option: &str) -> Result<(), ScanError> {
    if *value {
        Err(ScanError::DuplicateOption(option.to_owned()))
    } else {
        *value = true;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("{0}", usage())]
    Usage,
    #[error("required option is missing: {0}")]
    MissingOption(&'static str),
    #[error("option requires a value: {0}")]
    MissingValue(String),
    #[error("option must be an integer: {0}")]
    InvalidInteger(String),
    #[error("option was supplied more than once: {0}")]
    DuplicateOption(String),
    #[error("unknown scan option: {0}")]
    UnknownOption(String),
    #[error("every scan budget must be greater than zero")]
    InvalidBudget,
    #[error("--propose-patches requires --allow-patch-application")]
    PatchApprovalRequired,
    #[error("--propose-patches cannot be combined with --admit-only")]
    PatchProposalRequiresLiveScan,
    #[error("unsupported optional tool: {0}")]
    UnsupportedTool(String),
    #[error("requested optional tool is not installed or not on PATH: {0}")]
    ToolUnavailable(String),
    #[error(
        "repository does not contain a supported Python, TypeScript, JavaScript, or Go project"
    )]
    UnsupportedRepository,
    #[error(
        "repository has uncommitted changes; review them and pass --allow-dirty to approve this snapshot"
    )]
    DirtyRepository,
    #[error("output directory already exists: {0}")]
    OutputCollision(PathBuf),
    #[error("output directory must be outside the authorized repository: {0}")]
    UnsafeOutput(PathBuf),
    #[error("repository ingestion task failed: {0}")]
    IngestionTask(String),
    #[error("repository admission failed: {0}")]
    Repository(#[from] edsa_core::RepositoryError),
    #[error("provider admission failed: {0}")]
    Provider(#[from] edsa_model_providers::ProviderError),
    #[error("run storage failed: {0}")]
    Store(#[from] edsa_evidence::RunStoreError),
    #[error("live orchestration failed: {0}")]
    Orchestration(#[from] edsa_agent_runtime::OrchestrationError),
    #[error("run report failed: {0}")]
    Report(#[from] crate::run_report::RunReportError),
    #[error("live patch workflow failed: {0}")]
    Patch(#[from] crate::patch::PatchError),
    #[error("path resolution failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::process::Command;

    use edsa_core::{ProviderMetadata, RunApprovals, RunBudget};
    use tokio_util::sync::CancellationToken;

    use super::{ScanArguments, ScanError, execute_with_admitted_provider, parse};

    fn complete_arguments() -> Vec<String> {
        [
            ".",
            "--output",
            "../run",
            "--max-tokens",
            "100",
            "--max-cost-microusd",
            "100",
            "--max-turns",
            "4",
            "--max-experiments",
            "3",
            "--timeout-seconds",
            "60",
        ]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect()
    }

    #[test]
    fn parses_complete_budget() {
        let arguments = parse(complete_arguments()).expect("valid scan arguments");
        assert_eq!(arguments.budget.maximum_turns, 4);
        assert_eq!(arguments.repository.to_string_lossy(), ".");
    }

    #[test]
    fn rejects_zero_and_duplicate_budgets() {
        let mut zero = complete_arguments();
        zero[4] = "0".into();
        assert!(matches!(parse(zero), Err(ScanError::InvalidBudget)));

        let mut duplicate = complete_arguments();
        duplicate.extend(["--max-turns".into(), "2".into()]);
        assert!(matches!(
            parse(duplicate),
            Err(ScanError::DuplicateOption(_))
        ));
    }

    #[tokio::test]
    async fn cancellation_is_written_to_the_run_event_stream() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let repository = temporary.path().join("repository");
        fs::create_dir(&repository).expect("repository directory");
        fs::write(repository.join("app.py"), "print('fixture')\n").expect("source file");
        for arguments in [
            vec!["init"],
            vec!["config", "user.email", "tests@example.invalid"],
            vec!["config", "user.name", "EDSA Tests"],
            vec!["add", "app.py"],
            vec!["commit", "-m", "fixture"],
        ] {
            assert!(
                Command::new("git")
                    .arg("-C")
                    .arg(&repository)
                    .args(arguments)
                    .status()
                    .expect("git should start")
                    .success()
            );
        }
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let output = temporary.path().join("cancelled-run");
        let outcome = execute_with_admitted_provider(
            ScanArguments {
                repository,
                output: output.clone(),
                budget: RunBudget {
                    maximum_model_tokens: 1,
                    maximum_cost_microusd: 1,
                    maximum_turns: 1,
                    maximum_experiments: 1,
                    maximum_wall_time_seconds: 60,
                },
                approvals: RunApprovals::default(),
                optional_tools: BTreeSet::new(),
                admit_only: true,
                propose_patches: false,
            },
            cancellation,
            ProviderMetadata {
                provider: "openai-compatible".into(),
                model: "admitted-test-model".into(),
            },
        )
        .await
        .expect("cancelled admission remains durable");
        assert_eq!(outcome.status, edsa_core::RunStatus::Cancelled);
        let events = fs::read_to_string(output.join("events.jsonl")).expect("events");
        assert!(
            events
                .lines()
                .last()
                .is_some_and(|line| line.contains("cancelled"))
        );
    }
}
