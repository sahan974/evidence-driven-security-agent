use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use edsa_agent_runtime::roles::{
    AgentRole, EvidenceCriticContract, EvidenceCriticInput, EvidenceRecommendation,
};
use edsa_agent_runtime::{
    AgentRuntime, BudgetDimension, EvidenceAction, HypothesisCandidate, HypothesisDisposition,
    HypothesisScheduler, RuntimeBudget, RuntimeError,
};
use edsa_core::{
    ConfirmationPolicy, EvidenceAssessment, EvidenceId, EvidenceRef, HypothesisId, SCHEMA_VERSION,
    Verdict,
};
use edsa_model_providers::{
    MockProvider, ModelProvider, ModelRequest, ModelResponse, ProviderError, TokenUsage,
};
use serde_json::json;
use tokio_util::sync::CancellationToken;

fn assessment(oracle_passed: bool) -> EvidenceAssessment {
    EvidenceAssessment {
        schema_version: SCHEMA_VERSION,
        baseline_passed: true,
        oracle_passed,
        negative_control_passed: true,
        reproduced_runs: 2,
        evidence: vec![EvidenceRef {
            schema_version: SCHEMA_VERSION,
            id: EvidenceId::new("evidence-1"),
            media_type: "application/json".to_owned(),
            sha256: "a".repeat(64),
            size_bytes: 10,
        }],
    }
}

fn response(content: serde_json::Value) -> ModelResponse {
    ModelResponse {
        content,
        usage: TokenUsage {
            input_tokens: 10,
            output_tokens: 5,
            total_tokens: 15,
        },
        estimated_cost_microusd: 2,
        provider_request_id: Some("mock-1".to_owned()),
    }
}

#[tokio::test]
async fn critic_recommendations_cannot_bypass_confirmation_or_rejection_gates() {
    let provider = MockProvider::with_responses(vec![Ok(response(json!({
        "recommendation": "sufficient_for_gate_evaluation",
        "rationale": "machine evidence is complete",
        "missing_evidence": []
    })))]);
    let runtime = AgentRuntime::new(Arc::new(provider), "mock", RuntimeBudget::default());
    let run = runtime
        .execute::<EvidenceCriticContract>(
            &EvidenceCriticInput {
                hypothesis_id: HypothesisId::new("hyp-1"),
                assessment: assessment(true),
                evidence_documents: Vec::new(),
                repository_documents: Vec::new(),
            },
            0,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        run.output.recommendation,
        EvidenceRecommendation::SufficientForGateEvaluation
    );

    let policy = ConfirmationPolicy::default();
    assert_eq!(policy.verdict(&assessment(true)), Verdict::Confirmed);
    assert_eq!(policy.verdict(&assessment(false)), Verdict::Rejected);
}

#[test]
fn scheduler_prioritizes_and_can_branch_defer_reject_and_revisit() {
    let mut scheduler = HypothesisScheduler::default();
    let low = HypothesisCandidate::new(HypothesisId::new("low"), 200, 300, 200, 10).unwrap();
    let high = HypothesisCandidate::new(HypothesisId::new("high"), 900, 900, 800, 10).unwrap();
    scheduler.enqueue(low).unwrap();
    scheduler.enqueue(high.clone()).unwrap();
    assert_eq!(scheduler.next_candidate(), Some(high.clone()));

    let child = HypothesisCandidate::new(HypothesisId::new("child"), 700, 800, 900, 20).unwrap();
    scheduler
        .apply(EvidenceAction::Branch {
            parent: high.id.clone(),
            children: vec![child.clone()],
            evidence: "branch evidence".to_owned(),
        })
        .unwrap();
    scheduler
        .apply(EvidenceAction::Defer {
            id: child.id.clone(),
            reason: "await fixture".to_owned(),
        })
        .unwrap();
    assert!(matches!(
        scheduler.get(&child.id).unwrap().disposition,
        HypothesisDisposition::Deferred { .. }
    ));
    scheduler
        .apply(EvidenceAction::Revisit {
            id: child.id.clone(),
            evidence: "fixture arrived".to_owned(),
        })
        .unwrap();
    assert_eq!(scheduler.get(&child.id).unwrap().revisit_count, 1);
    scheduler
        .apply(EvidenceAction::Reject {
            id: child.id.clone(),
            reason: "negative control".to_owned(),
        })
        .unwrap();
    assert!(matches!(
        scheduler.get(&child.id).unwrap().disposition,
        HypothesisDisposition::Rejected { .. }
    ));
}

#[tokio::test]
async fn transient_provider_failure_is_retried_within_turn_budget() {
    let provider = MockProvider::with_responses(vec![
        Err(ProviderError::Timeout(Duration::from_millis(1))),
        Ok(response(json!({
            "recommendation": "needs_more_evidence",
            "rationale": "one more run",
            "missing_evidence": ["reproduction"]
        }))),
    ]);
    let runtime = AgentRuntime::new(Arc::new(provider), "mock", RuntimeBudget::default());
    let run = runtime
        .execute::<EvidenceCriticContract>(
            &EvidenceCriticInput {
                hypothesis_id: HypothesisId::new("hyp-1"),
                assessment: assessment(true),
                evidence_documents: Vec::new(),
                repository_documents: Vec::new(),
            },
            0,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(run.attempts, 2);
    assert_eq!(runtime.usage().unwrap().turns, 2);
}

#[tokio::test]
async fn malformed_structured_output_is_retried_within_role_limit() {
    let provider = MockProvider::with_responses(vec![
        Err(ProviderError::MalformedJson("truncated response".into())),
        Ok(response(json!({
            "recommendation": "needs_more_evidence",
            "rationale": "retry produced valid structured output",
            "missing_evidence": ["reproduction"]
        }))),
    ]);
    let runtime = AgentRuntime::new(Arc::new(provider), "mock", RuntimeBudget::default());
    let run = runtime
        .execute::<EvidenceCriticContract>(
            &EvidenceCriticInput {
                hypothesis_id: HypothesisId::new("hyp-structured-retry"),
                assessment: assessment(true),
                evidence_documents: Vec::new(),
                repository_documents: Vec::new(),
            },
            0,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(run.attempts, 2);
    assert_eq!(runtime.usage().unwrap().turns, 2);
}

#[derive(Debug)]
struct BlockingProvider;

#[async_trait]
impl ModelProvider for BlockingProvider {
    async fn complete(&self, _request: &ModelRequest) -> Result<ModelResponse, ProviderError> {
        std::future::pending().await
    }
}

#[tokio::test]
async fn cancellation_is_explicit_and_releases_concurrency() {
    let runtime = Arc::new(AgentRuntime::new(
        Arc::new(BlockingProvider),
        "mock",
        RuntimeBudget::default(),
    ));
    let cancellation = CancellationToken::new();
    let task = tokio::spawn({
        let runtime = Arc::clone(&runtime);
        let cancellation = cancellation.clone();
        async move {
            runtime
                .execute::<EvidenceCriticContract>(
                    &EvidenceCriticInput {
                        hypothesis_id: HypothesisId::new("hyp-1"),
                        assessment: assessment(true),
                        evidence_documents: Vec::new(),
                        repository_documents: Vec::new(),
                    },
                    0,
                    &cancellation,
                )
                .await
        }
    });
    tokio::task::yield_now().await;
    cancellation.cancel();
    assert!(matches!(task.await.unwrap(), Err(RuntimeError::Cancelled)));
    assert_eq!(runtime.usage().unwrap().active_calls, 0);
}

#[tokio::test]
async fn budget_exhaustion_returns_an_explicit_inconclusive_event() {
    let provider = MockProvider::with_responses(Vec::new());
    let runtime = AgentRuntime::new(
        Arc::new(provider),
        "mock",
        RuntimeBudget {
            maximum_turns: 0,
            ..RuntimeBudget::default()
        },
    );
    let error = runtime
        .execute::<EvidenceCriticContract>(
            &EvidenceCriticInput {
                hypothesis_id: HypothesisId::new("hyp-1"),
                assessment: assessment(true),
                evidence_documents: Vec::new(),
                repository_documents: Vec::new(),
            },
            0,
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        RuntimeError::Budget(edsa_agent_runtime::RuntimeEvent::BudgetExhausted {
            dimension: BudgetDimension::Turns,
            ..
        })
    ));
}

#[test]
fn all_roles_have_independent_configs_and_no_verdict_capability() {
    let runtime = AgentRuntime::new(
        Arc::new(MockProvider::default()),
        "mock",
        RuntimeBudget::default(),
    );
    assert_eq!(runtime.configurations().len(), 7);
    for role in [
        AgentRole::Mapper,
        AgentRole::HypothesisPlanner,
        AgentRole::ExperimentDesigner,
        AgentRole::EvidenceCritic,
        AgentRole::PatchAgent,
        AgentRole::VariantHunter,
        AgentRole::Reviewer,
    ] {
        let configuration = runtime.configurations().get(&role).unwrap();
        assert_eq!(configuration.role, role);
        assert!(!configuration.system_instruction.is_empty());
    }
}
