use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use edsa_core::{
    EvidenceAssessment, Hypothesis, HypothesisId, RepositoryInventory, RunStatus, SCHEMA_VERSION,
    Signal, SignalId, SignalSource, Verdict,
};
use edsa_evidence::{ArtifactStore, RunStore};
use edsa_model_providers::ModelProvider;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::prompt_security;
use crate::roles::{
    AgentRole, EvidenceCriticContract, EvidenceCriticInput, EvidenceRecommendation,
    ExperimentDesignerContract, ExperimentDesignerInput, FileSummary, HypothesisPlannerContract,
    HypothesisPlannerInput, MapperContract, MapperInput, ProposedTools, RepositoryDocument,
    ReviewerContract, ReviewerInput, RoleContract, ToolRequest,
};
use crate::{
    AgentRuntime, EvidenceAction, HypothesisCandidate, HypothesisScheduler, RoleRun, RuntimeBudget,
    RuntimeError, RuntimeUsage, SchedulerError, ToolDispatcher, execute_hypothesis,
};

const MAXIMUM_DOCUMENT_BYTES: usize = 12 * 1024;
const MAXIMUM_PROJECTION_BYTES: usize = 72 * 1024;
const MAXIMUM_HYPOTHESES_PER_RUN: usize = 3;

#[derive(Clone, Debug, Serialize)]
pub struct OrchestrationSummary {
    pub roles_completed: BTreeSet<AgentRole>,
    pub signals_created: usize,
    pub hypotheses_created: usize,
    pub hypotheses_processed: usize,
    pub adapters_selected: BTreeSet<String>,
    pub verdicts: BTreeMap<String, usize>,
    pub usage: RuntimeUsage,
}

#[derive(Debug)]
pub struct LiveOrchestrator {
    runtime: AgentRuntime,
    dispatcher: ToolDispatcher,
    repository_root: PathBuf,
}

impl LiveOrchestrator {
    #[must_use]
    pub fn new(
        provider: Arc<dyn ModelProvider>,
        model: impl Into<String>,
        budget: RuntimeBudget,
        repository_root: impl Into<PathBuf>,
        inventory: &RepositoryInventory,
    ) -> Self {
        let repository_root = repository_root.into();
        let runtime = AgentRuntime::new(provider, model, budget);
        let dispatcher = ToolDispatcher::new(
            repository_root.clone(),
            inventory,
            runtime.configurations().clone(),
        );
        Self {
            runtime,
            dispatcher,
            repository_root,
        }
    }

    /// Executes the live mapper-to-reviewer investigation loop.
    ///
    /// Model output remains advisory. This phase records proposals and scheduling
    /// decisions but cannot assign a vulnerability verdict or complete an evidence gate.
    ///
    /// # Errors
    /// Returns an error after recording provider, schema, policy, budget, or storage failures.
    #[allow(clippy::too_many_lines)]
    pub async fn run(
        &self,
        inventory: &RepositoryInventory,
        store: &mut RunStore,
        cancellation: &CancellationToken,
    ) -> Result<OrchestrationSummary, OrchestrationError> {
        let started = Instant::now();
        store.append_record(
            RunStatus::Running,
            "live multi-agent orchestration started",
            json!({ "stage": "orchestration_started" }),
        )?;
        let mapper_input = mapper_input(&self.repository_root, inventory)?;
        let mapper = self
            .execute_role::<MapperContract>(
                &mapper_input,
                "role:mapper",
                started,
                store,
                cancellation,
            )
            .await?;
        let builtin =
            edsa_signal_import::collect_builtin_signals(&self.repository_root, inventory)?;
        let signals = normalize_signals(&mapper.output.signals, builtin, inventory, store)?;

        let planner_input = HypothesisPlannerInput {
            signals: signals.clone(),
        };
        let planner = self
            .execute_role::<HypothesisPlannerContract>(
                &planner_input,
                "role:hypothesis_planner",
                started,
                store,
                cancellation,
            )
            .await?;
        let (hypothesis_registry, mut scheduler) =
            normalize_hypotheses(&planner.output.hypotheses, &signals, store)?;

        let mut roles_completed = BTreeSet::from([AgentRole::Mapper, AgentRole::HypothesisPlanner]);
        let mut processed = 0_usize;
        let mut processed_hypotheses = BTreeSet::new();
        let mut adapters_selected = BTreeSet::new();
        let mut verdicts = BTreeMap::new();
        while processed < MAXIMUM_HYPOTHESES_PER_RUN {
            let Some(candidate) = scheduler.next_candidate() else {
                break;
            };
            if !processed_hypotheses.insert(candidate.id.clone()) {
                store.append_record(
                    RunStatus::Running,
                    "duplicate hypothesis revisit skipped to preserve adapter coverage",
                    json!({ "stage": "revisit_skipped", "hypothesis_id": candidate.id }),
                )?;
                continue;
            }
            let current_hypothesis = hypothesis_registry
                .get(&candidate.id)
                .ok_or_else(|| OrchestrationError::MissingHypothesis(candidate.id.clone()))?;
            record_decision(
                store,
                "prioritized",
                current_hypothesis,
                &json!({
                    "priority": candidate.priority(),
                    "confidence": candidate.confidence,
                    "impact": candidate.impact,
                    "information_gain": candidate.information_gain
                }),
            )?;

            let designer_input = ExperimentDesignerInput {
                hypothesis: current_hypothesis.clone(),
                available_test_commands: available_test_commands(inventory),
            };
            let designer = self
                .execute_role::<ExperimentDesignerContract>(
                    &designer_input,
                    &format!(
                        "role:experiment_designer:{}",
                        current_hypothesis.id.as_str()
                    ),
                    started,
                    store,
                    cancellation,
                )
                .await?;
            roles_completed.insert(AgentRole::ExperimentDesigner);
            store.append_record(
                RunStatus::Running,
                "experiment proposals recorded for typed adapter validation",
                json!({
                    "stage": "experiment_proposals",
                    "hypothesis_id": current_hypothesis.id,
                    "proposals": designer.output.experiments
                }),
            )?;

            let experiment_key = format!("experiment:{}", current_hypothesis.id.as_str());
            let (experiment, restored_experiment) =
                if let Some(execution) = store.checkpoint(&experiment_key)? {
                    (Ok(execution), true)
                } else {
                    (
                        execute_hypothesis(
                            &self.repository_root,
                            inventory,
                            current_hypothesis,
                            &signals,
                            store,
                            cancellation,
                        )
                        .await,
                        false,
                    )
                };
            let (assessment, machine_verdict) = match experiment {
                Ok(execution) => {
                    let machine_verdict = execution.verdict;
                    let assessment = execution.assessment.clone();
                    adapters_selected
                        .insert(format!("{:?}", execution.adapter).to_ascii_lowercase());
                    *verdicts
                        .entry(format!("{:?}", execution.verdict).to_ascii_lowercase())
                        .or_insert(0) += 1;
                    if !restored_experiment {
                        store.append_record(RunStatus::Running, "deterministic experiment completed", json!({
                            "stage": "deterministic_experiment", "hypothesis_id": current_hypothesis.id,
                            "execution": &execution,
                            "checkpoint_key": experiment_key,
                            "checkpoint": &execution
                        }))?;
                    }
                    (assessment, machine_verdict)
                }
                Err(error) => {
                    *verdicts.entry("inconclusive".into()).or_insert(0) += 1;
                    store.append_record(
                        RunStatus::Running,
                        "experiment proposal rejected by adapter boundary",
                        json!({
                            "stage": "experiment_rejected", "hypothesis_id": current_hypothesis.id,
                            "hypothesis": current_hypothesis,
                            "signal": signals.iter().find(|signal| current_hypothesis.signal_ids.contains(&signal.id)),
                            "error": error.to_string(), "model_commands_executed": false
                        }),
                    )?;
                    (
                        EvidenceAssessment {
                            schema_version: SCHEMA_VERSION,
                            baseline_passed: false,
                            oracle_passed: false,
                            negative_control_passed: false,
                            reproduced_runs: 0,
                            evidence: Vec::new(),
                        },
                        Verdict::Inconclusive,
                    )
                }
            };
            let critic = self
                .execute_role::<EvidenceCriticContract>(
                    &EvidenceCriticInput {
                        hypothesis_id: current_hypothesis.id.clone(),
                        assessment: assessment.clone(),
                    },
                    &format!("role:evidence_critic:{}", current_hypothesis.id.as_str()),
                    started,
                    store,
                    cancellation,
                )
                .await?;
            roles_completed.insert(AgentRole::EvidenceCritic);

            let reviewer = self
                .execute_role::<ReviewerContract>(
                    &ReviewerInput {
                        hypothesis_id: current_hypothesis.id.clone(),
                        evidence: Vec::new(),
                        proposed_diff: None,
                        completed_gate_names: Vec::new(),
                    },
                    &format!("role:reviewer:{}", current_hypothesis.id.as_str()),
                    started,
                    store,
                    cancellation,
                )
                .await?;
            roles_completed.insert(AgentRole::Reviewer);

            apply_review_decision(
                &mut scheduler,
                current_hypothesis,
                machine_verdict,
                critic.output.recommendation,
                &reviewer.output.requested_experiments,
                store,
            )?;
            processed = processed.saturating_add(1);
        }

        let usage = self.runtime.usage()?;
        let summary = OrchestrationSummary {
            roles_completed,
            signals_created: signals.len(),
            hypotheses_created: hypothesis_registry.len(),
            hypotheses_processed: processed,
            adapters_selected,
            verdicts,
            usage,
        };
        let terminal = if summary.verdicts.get("confirmed").copied().unwrap_or(0) > 0
            || summary.verdicts.get("rejected").copied().unwrap_or(0) > 0
        {
            RunStatus::Completed
        } else {
            RunStatus::Inconclusive
        };
        store.append_record(
            terminal,
            "live role loop and deterministic experiment gates completed",
            serde_json::to_value(&summary)?,
        )?;
        Ok(summary)
    }

    async fn execute_role<R>(
        &self,
        input: &R::Input,
        checkpoint_key: &str,
        started: Instant,
        store: &mut RunStore,
        cancellation: &CancellationToken,
    ) -> Result<RoleRun<R::Output>, OrchestrationError>
    where
        R: RoleContract,
        R::Output: ProposedTools,
    {
        if let Some(checkpoint) = store.checkpoint::<RoleCheckpoint<R::Output>>(checkpoint_key)? {
            return Ok(checkpoint.into_role_run());
        }
        let configuration = self
            .runtime
            .configurations()
            .get(&R::ROLE)
            .ok_or(RuntimeError::MissingRoleConfiguration(R::ROLE))?;
        store.append_record(
            RunStatus::Running,
            format!("{:?} prompt recorded", R::ROLE),
            json!({
                "stage": "role_prompt",
                "role": R::ROLE,
                "system": configuration.system_instruction,
                "prompt": prompt_security::envelope(input)?
            }),
        )?;
        let elapsed = started.elapsed().as_secs();
        let run = match self
            .runtime
            .execute::<R>(input, elapsed, cancellation)
            .await
        {
            Ok(run) => run,
            Err(error) => {
                store.append_record(
                    RunStatus::Running,
                    format!("{:?} role failed", R::ROLE),
                    runtime_error_record(R::ROLE, &error),
                )?;
                return Err(error.into());
            }
        };
        store.append_record(
            RunStatus::Running,
            format!("{:?} response recorded", R::ROLE),
            json!({
                "stage": "role_response",
                "role": R::ROLE,
                "response": &run.output,
                "usage": &run.usage,
                "estimated_cost_microusd": run.estimated_cost_microusd,
                "attempts": run.attempts,
                "provider_request_id": &run.provider_request_id,
                "runtime_events": &run.events,
                "checkpoint_key": checkpoint_key,
                "checkpoint": {
                    "output": &run.output,
                    "usage": &run.usage,
                    "estimated_cost_microusd": run.estimated_cost_microusd,
                    "attempts": run.attempts,
                    "provider_request_id": &run.provider_request_id,
                    "events": &run.events
                }
            }),
        )?;
        self.dispatch_requests(R::ROLE, run.output.tool_requests(), store)?;
        Ok(run)
    }

    fn dispatch_requests(
        &self,
        role: AgentRole,
        requests: &[ToolRequest],
        store: &mut RunStore,
    ) -> Result<(), OrchestrationError> {
        let artifacts = ArtifactStore::open(store.root().join("artifacts"))?;
        for request in requests {
            let result = self
                .dispatcher
                .dispatch_with_evidence(role, request, &artifacts);
            store.append_record(
                RunStatus::Running,
                format!("{role:?} tool request evaluated"),
                match result {
                    Ok(output) => json!({
                        "stage": "tool_result", "role": role, "request": request,
                        "allowed": true, "result": output
                    }),
                    Err(error) => json!({
                        "stage": "tool_result", "role": role, "request": request,
                        "allowed": false, "error": error.to_string()
                    }),
                },
            )?;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct RoleCheckpoint<T> {
    output: T,
    usage: edsa_model_providers::TokenUsage,
    estimated_cost_microusd: u64,
    attempts: u8,
    provider_request_id: Option<String>,
    events: Vec<crate::RuntimeEvent>,
}

impl<T> RoleCheckpoint<T> {
    fn into_role_run(self) -> RoleRun<T> {
        RoleRun {
            output: self.output,
            usage: self.usage,
            estimated_cost_microusd: self.estimated_cost_microusd,
            attempts: self.attempts,
            provider_request_id: self.provider_request_id,
            events: self.events,
        }
    }
}

fn runtime_error_record(role: AgentRole, error: &RuntimeError) -> Value {
    if let RuntimeError::TypedOutput {
        response,
        usage,
        estimated_cost_microusd,
        provider_request_id,
        ..
    } = error
    {
        json!({
            "stage": "role_error",
            "role": role,
            "error": error.to_string(),
            "rejected_response": response,
            "usage": usage,
            "estimated_cost_microusd": estimated_cost_microusd,
            "provider_request_id": provider_request_id
        })
    } else {
        json!({ "stage": "role_error", "role": role, "error": error.to_string() })
    }
}

fn mapper_input(
    repository_root: &Path,
    inventory: &RepositoryInventory,
) -> Result<MapperInput, OrchestrationError> {
    let files = inventory
        .files
        .iter()
        .map(|file| FileSummary {
            relative_path: file.relative_path.clone(),
            sha256: file.sha256.clone(),
            size_bytes: file.size_bytes,
        })
        .collect();
    let mut documents = Vec::new();
    let mut projected = 0_usize;
    for file in &inventory.files {
        if projected >= MAXIMUM_PROJECTION_BYTES || !security_source(&file.relative_path) {
            continue;
        }
        let path =
            edsa_core::resolve_repository_path(repository_root, Path::new(&file.relative_path))?;
        let bytes = fs::read(path)?;
        let remaining = MAXIMUM_PROJECTION_BYTES.saturating_sub(projected);
        let retained = bytes.len().min(MAXIMUM_DOCUMENT_BYTES).min(remaining);
        documents.push(RepositoryDocument {
            relative_path: file.relative_path.clone(),
            content: String::from_utf8_lossy(&bytes[..retained]).into_owned(),
            truncated: retained < bytes.len(),
        });
        projected = projected.saturating_add(retained);
    }
    if documents.is_empty() {
        return Err(OrchestrationError::EmptyProjection);
    }
    Ok(MapperInput {
        snapshot: inventory.snapshot.clone(),
        files,
        documents,
    })
}

fn security_source(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "py" | "pyi" | "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs" | "go"
            )
        })
}

fn normalize_signals(
    proposals: &[crate::roles::SignalProposal],
    builtin: Vec<Signal>,
    inventory: &RepositoryInventory,
    store: &mut RunStore,
) -> Result<Vec<Signal>, OrchestrationError> {
    let admitted = inventory
        .files
        .iter()
        .map(|file| file.relative_path.as_str())
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    let mut signals = builtin;
    for signal in &signals {
        seen.insert(format!(
            "{}:{}:{}",
            signal.rule, signal.relative_path, signal.start_line
        ));
    }
    for proposal in proposals {
        if !admitted.contains(proposal.relative_path.as_str()) || proposal.start_line == 0 {
            store.append_record(
                RunStatus::Running,
                "invalid mapper proposal rejected",
                json!({ "stage": "proposal_rejected", "proposal": proposal }),
            )?;
            continue;
        }
        let key = format!(
            "{}:{}:{}",
            proposal.rule, proposal.relative_path, proposal.start_line
        );
        if !seen.insert(key.clone()) {
            store.append_record(
                RunStatus::Running,
                "repeated mapper proposal ignored",
                json!({ "stage": "proposal_repeated", "proposal": proposal }),
            )?;
            continue;
        }
        signals.push(Signal {
            schema_version: SCHEMA_VERSION,
            id: SignalId::new(stable_id("signal", &key)),
            source: SignalSource::ModelProposal,
            rule: proposal.rule.clone(),
            relative_path: proposal.relative_path.clone(),
            start_line: proposal.start_line,
            message: proposal.rationale.clone(),
            metadata: BTreeMap::new(),
        });
    }
    if signals.is_empty() {
        return Err(OrchestrationError::NoValidSignals);
    }
    Ok(signals)
}

fn normalize_hypotheses(
    proposals: &[crate::roles::HypothesisProposal],
    signals: &[Signal],
    store: &mut RunStore,
) -> Result<(BTreeMap<HypothesisId, Hypothesis>, HypothesisScheduler), OrchestrationError> {
    let signal_ids = signals
        .iter()
        .map(|signal| signal.id.clone())
        .collect::<BTreeSet<_>>();
    let mut registry = BTreeMap::new();
    let mut scheduler = HypothesisScheduler::default();
    let mut seen = BTreeSet::new();
    let mut scheduled_adapters = BTreeSet::new();
    for proposal in proposals {
        if proposal.supporting_signal_ids.is_empty()
            || proposal
                .supporting_signal_ids
                .iter()
                .any(|id| !signal_ids.contains(id))
        {
            store.append_record(
                RunStatus::Running,
                "hypothesis with unknown signal was rejected",
                json!({ "stage": "proposal_rejected", "proposal": proposal }),
            )?;
            continue;
        }
        let key = format!("{}:{}", proposal.title, proposal.claim);
        if !seen.insert(key.clone()) {
            store.append_record(
                RunStatus::Running,
                "repeated hypothesis proposal ignored",
                json!({ "stage": "proposal_repeated", "proposal": proposal }),
            )?;
            continue;
        }
        let mut signals_by_adapter = BTreeMap::<(&'static str, &'static str), Vec<SignalId>>::new();
        for signal_id in &proposal.supporting_signal_ids {
            if let Some(signal) = signals.iter().find(|signal| signal.id == *signal_id) {
                if let Some(adapter) = adapter_key(&signal.relative_path) {
                    signals_by_adapter
                        .entry((adapter, experiment_class(adapter, signal)))
                        .or_default()
                        .push(signal.id.clone());
                }
            }
        }

        // A cross-language proposal explains one issue with several pieces of
        // evidence. It must not be executed as one unit, because each adapter
        // requires a source location in its own language. Split it before it
        // reaches the scheduler so selection and execution use the same scope.
        for ((adapter, class), signal_ids) in signals_by_adapter {
            let id =
                HypothesisId::new(stable_id("hypothesis", &format!("{key}:{adapter}:{class}")));
            let normalized = Hypothesis {
                schema_version: SCHEMA_VERSION,
                id: id.clone(),
                title: format!("{} ({})", proposal.title, adapter_display_name(adapter)),
                claim: proposal.claim.clone(),
                weakness: proposal.weakness.clone(),
                signal_ids,
            };
            let is_expressible = safely_expressible(
                adapter,
                &proposal.title,
                &proposal.claim,
                &proposal.weakness,
            );
            if is_expressible {
                enqueue_supported(
                    &mut scheduler,
                    &mut scheduled_adapters,
                    adapter,
                    HypothesisCandidate::new(
                        id.clone(),
                        proposal.confidence,
                        proposal.impact,
                        proposal.information_gain,
                        proposal.expected_cost_microusd,
                    )?,
                )?;
            }
            registry.insert(id, normalized);
        }
    }
    add_adapter_coverage(
        signals,
        &mut registry,
        &mut scheduler,
        &mut scheduled_adapters,
    )?;
    if registry.is_empty() {
        return Err(OrchestrationError::NoValidHypotheses);
    }
    Ok((registry, scheduler))
}

fn enqueue_supported(
    scheduler: &mut HypothesisScheduler,
    covered_adapters: &mut BTreeSet<&'static str>,
    adapter: &'static str,
    candidate: HypothesisCandidate,
) -> Result<(), SchedulerError> {
    scheduler.enqueue(candidate)?;
    covered_adapters.insert(adapter);
    Ok(())
}

fn add_adapter_coverage(
    signals: &[Signal],
    registry: &mut BTreeMap<HypothesisId, Hypothesis>,
    scheduler: &mut HypothesisScheduler,
    covered_adapters: &mut BTreeSet<&'static str>,
) -> Result<(), OrchestrationError> {
    for adapter in ["python", "typescript", "go"] {
        if covered_adapters.contains(adapter) {
            continue;
        }
        let Some(signal) = signals
            .iter()
            .filter(|signal| adapter_key(&signal.relative_path) == Some(adapter))
            .max_by_key(|signal| signal.start_line)
        else {
            continue;
        };
        let key = format!("adapter-coverage:{adapter}:{}", signal.id.as_str());
        let id = HypothesisId::new(stable_id("hypothesis", &key));
        let hypothesis = Hypothesis {
            schema_version: SCHEMA_VERSION,
            id: id.clone(),
            title: format!("{} filesystem boundary", adapter_display_name(adapter)),
            claim: format!(
                "The path-handling operation at {}:{} may permit access outside its intended root",
                signal.relative_path, signal.start_line
            ),
            weakness: "CWE-22 filesystem path traversal".into(),
            signal_ids: vec![signal.id.clone()],
        };
        scheduler.enqueue(HypothesisCandidate::new(id.clone(), 100, 100, 100, 0)?)?;
        registry.insert(id, hypothesis);
        covered_adapters.insert(adapter);
    }
    Ok(())
}

fn adapter_key(path: &str) -> Option<&'static str> {
    match Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())?
        .to_ascii_lowercase()
        .as_str()
    {
        "py" | "pyi" => Some("python"),
        "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" => Some("typescript"),
        "go" => Some("go"),
        _ => None,
    }
}

fn experiment_class(adapter: &str, signal: &Signal) -> &'static str {
    let text = format!("{} {}", signal.rule, signal.message).to_ascii_lowercase();
    match adapter {
        "python" if contains_any(&text, &["command", "shell", "subprocess"]) => "command",
        "typescript" if contains_any(&text, &["ssrf", "request", "url", "fetch"]) => "network",
        "go" if contains_any(
            &text,
            &[
                "panic",
                "malformed",
                "out_of_bounds",
                "out-of-bounds",
                "slice",
            ],
        ) =>
        {
            "malformed"
        }
        "python" | "typescript" | "go" => "filesystem",
        _ => "unsupported",
    }
}

fn contains_any(text: &str, terms: &[&str]) -> bool {
    terms.iter().any(|term| text.contains(term))
}

fn safely_expressible(adapter: &str, title: &str, claim: &str, weakness: &str) -> bool {
    let text = format!("{title} {claim} {weakness}").to_ascii_lowercase();
    match adapter {
        "python" => ["path", "travers", "command", "inject"]
            .iter()
            .any(|term| text.contains(term)),
        "typescript" => ["path", "travers", "ssrf", "server-side request"]
            .iter()
            .any(|term| text.contains(term)),
        "go" => ["path", "filesystem", "panic", "malformed"]
            .iter()
            .any(|term| text.contains(term)),
        _ => false,
    }
}

fn adapter_display_name(adapter: &str) -> &'static str {
    match adapter {
        "python" => "Python",
        "typescript" => "TypeScript or JavaScript",
        "go" => "Go",
        _ => "Unsupported",
    }
}

fn apply_review_decision(
    scheduler: &mut HypothesisScheduler,
    hypothesis: &Hypothesis,
    machine_verdict: Verdict,
    recommendation: EvidenceRecommendation,
    requested_experiments: &[String],
    store: &mut RunStore,
) -> Result<(), OrchestrationError> {
    match machine_verdict {
        Verdict::Confirmed => {
            scheduler.apply(EvidenceAction::Complete {
                id: hypothesis.id.clone(),
                evidence: "deterministic confirmation gates passed".into(),
            })?;
            record_decision(
                store,
                "confirmed_by_machine_gates",
                hypothesis,
                &Value::Null,
            )?;
            return Ok(());
        }
        Verdict::Rejected => {
            scheduler.apply(EvidenceAction::Reject {
                id: hypothesis.id.clone(),
                reason: "deterministic oracle did not reproduce with a valid baseline and control"
                    .into(),
            })?;
            record_decision(store, "rejected_by_machine_gates", hypothesis, &Value::Null)?;
            return Ok(());
        }
        Verdict::Suspected | Verdict::Inconclusive => {}
    }
    match recommendation {
        EvidenceRecommendation::EvidenceContradictsClaim => {
            scheduler.apply(EvidenceAction::Reject {
                id: hypothesis.id.clone(),
                reason: "critic found the available record contradicts the claim".into(),
            })?;
            record_decision(store, "rejected", hypothesis, &Value::Null)?;
        }
        EvidenceRecommendation::NeedsMoreEvidence => {
            scheduler.apply(EvidenceAction::Defer {
                id: hypothesis.id.clone(),
                reason: "deterministic experiment evidence is not available yet".into(),
            })?;
            record_decision(store, "deferred", hypothesis, &Value::Null)?;
            if !requested_experiments.is_empty() {
                scheduler.apply(EvidenceAction::Revisit {
                    id: hypothesis.id.clone(),
                    evidence: "reviewer requested bounded follow-up experiments".into(),
                })?;
                record_decision(
                    store,
                    "revisited",
                    hypothesis,
                    &json!({ "requested_experiments": requested_experiments }),
                )?;
            }
        }
        EvidenceRecommendation::SufficientForGateEvaluation => {
            scheduler.apply(EvidenceAction::Complete {
                id: hypothesis.id.clone(),
                evidence: "proposal review complete; deterministic gates remain authoritative"
                    .into(),
            })?;
            record_decision(
                store,
                "closed_for_gate_evaluation",
                hypothesis,
                &Value::Null,
            )?;
        }
    }
    Ok(())
}

fn record_decision(
    store: &mut RunStore,
    decision: &str,
    hypothesis: &Hypothesis,
    detail: &Value,
) -> Result<(), OrchestrationError> {
    store.append_record(
        RunStatus::Running,
        format!("hypothesis {decision}"),
        json!({
            "stage": "scheduling_decision",
            "decision": decision,
            "hypothesis_id": hypothesis.id,
            "detail": detail
        }),
    )?;
    Ok(())
}

fn available_test_commands(inventory: &RepositoryInventory) -> Vec<Vec<String>> {
    use edsa_core::Language;
    let mut commands = Vec::new();
    if inventory.detection.languages.contains(&Language::Python) {
        commands.push(vec![
            "python".into(),
            "-m".into(),
            "pytest".into(),
            "-q".into(),
        ]);
    }
    if inventory
        .detection
        .languages
        .contains(&Language::TypeScript)
        || inventory
            .detection
            .languages
            .contains(&Language::JavaScript)
    {
        commands.push(vec![
            "npm".into(),
            "test".into(),
            "--".into(),
            "--runInBand".into(),
        ]);
    }
    if inventory.detection.languages.contains(&Language::Go) {
        commands.push(vec!["go".into(), "test".into(), "./...".into()]);
    }
    commands
}

fn stable_id(prefix: &str, value: &str) -> String {
    let digest = format!("{:x}", Sha256::digest(value.as_bytes()));
    format!("{prefix}-{}", &digest[..16])
}

#[derive(Debug, Error)]
pub enum OrchestrationError {
    #[error("repository projection contains no supported source documents")]
    EmptyProjection,
    #[error("mapper returned no valid repository signals")]
    NoValidSignals,
    #[error("planner returned no valid hypotheses")]
    NoValidHypotheses,
    #[error("scheduled hypothesis is missing from the normalized registry: {0:?}")]
    MissingHypothesis(HypothesisId),
    #[error("agent role failed: {0}")]
    Runtime(#[from] RuntimeError),
    #[error("scheduler failed: {0}")]
    Scheduler(#[from] SchedulerError),
    #[error("run storage failed: {0}")]
    Store(#[from] edsa_evidence::RunStoreError),
    #[error("evidence artifact access failed: {0}")]
    Artifact(#[from] edsa_evidence::ArtifactError),
    #[error("prompt or event JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("repository path policy failed: {0}")]
    PathPolicy(#[from] edsa_core::PathPolicyError),
    #[error("repository projection I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("built-in signal collection failed: {0}")]
    Builtin(#[from] edsa_signal_import::BuiltinError),
}

#[cfg(test)]
mod scheduling_tests {
    use std::collections::BTreeMap;

    use edsa_core::{SCHEMA_VERSION, Signal, SignalId, SignalSource};

    use super::{
        BTreeSet, HypothesisCandidate, HypothesisId, HypothesisScheduler, enqueue_supported,
        experiment_class,
    };

    #[test]
    fn different_findings_in_one_language_are_both_scheduled() {
        let mut scheduler = HypothesisScheduler::default();
        let mut coverage = BTreeSet::new();
        for id in ["go-panic", "go-filesystem"] {
            enqueue_supported(
                &mut scheduler,
                &mut coverage,
                "go",
                HypothesisCandidate::new(HypothesisId::new(id), 100, 100, 100, 0).unwrap(),
            )
            .unwrap();
        }
        assert!(scheduler.next_candidate().is_some());
        assert!(scheduler.next_candidate().is_some());
        assert!(scheduler.next_candidate().is_none());
        assert_eq!(coverage.len(), 1);
    }

    #[test]
    fn go_signals_with_different_experiment_classes_do_not_share_a_hypothesis() {
        let filesystem = Signal {
            schema_version: SCHEMA_VERSION,
            id: SignalId::new("filesystem"),
            source: SignalSource::BuiltInRule,
            rule: "unbounded_file_read".into(),
            relative_path: "fixture.go".into(),
            start_line: 1,
            message: "Input reaches os.ReadFile".into(),
            metadata: BTreeMap::new(),
        };
        let malformed = Signal {
            rule: "out_of_bounds_slice_access".into(),
            message: "Malformed input indexes a short slice".into(),
            ..filesystem.clone()
        };
        assert_eq!(experiment_class("go", &filesystem), "filesystem");
        assert_eq!(experiment_class("go", &malformed), "malformed");
    }
}
