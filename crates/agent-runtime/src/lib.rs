//! Typed multi-agent orchestration with deterministic scheduling and budgets.

pub mod roles;
pub mod scheduler;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use edsa_core::SCHEMA_VERSION;
use edsa_model_providers::{
    MessageRole, ModelMessage, ModelProvider, ModelRequest, ProviderError, TokenUsage,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

pub use roles::*;
pub use scheduler::*;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeBudget {
    pub maximum_turns: u64,
    pub maximum_wall_time_seconds: u64,
    pub maximum_model_tokens: u64,
    pub maximum_cost_microusd: u64,
    pub maximum_experiments: u32,
    pub maximum_concurrency: u32,
}

impl Default for RuntimeBudget {
    fn default() -> Self {
        Self {
            maximum_turns: 100,
            maximum_wall_time_seconds: 3_600,
            maximum_model_tokens: 1_000_000,
            maximum_cost_microusd: 5_000_000,
            maximum_experiments: 50,
            maximum_concurrency: 4,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeUsage {
    pub turns: u64,
    pub model_tokens: u64,
    pub cost_microusd: u64,
    pub experiments: u32,
    pub active_calls: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetDimension {
    Turns,
    WallTime,
    ModelTokens,
    Cost,
    Experiments,
    Concurrency,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetOutcome {
    Deferred,
    Inconclusive,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuntimeEvent {
    BudgetExhausted {
        schema_version: u16,
        role: AgentRole,
        dimension: BudgetDimension,
        used: u64,
        limit: u64,
        outcome: BudgetOutcome,
    },
}

#[derive(Clone, Debug)]
struct PlannedWork {
    model_tokens: u64,
    cost_microusd: u64,
    experiment: bool,
}

#[derive(Clone, Debug)]
struct Admission {
    role: AgentRole,
    planned: PlannedWork,
}

#[derive(Debug)]
struct BudgetController {
    limits: RuntimeBudget,
    usage: RuntimeUsage,
    reserved_tokens: u64,
    reserved_cost: u64,
}

impl BudgetController {
    fn new(limits: RuntimeBudget) -> Self {
        Self {
            limits,
            usage: RuntimeUsage::default(),
            reserved_tokens: 0,
            reserved_cost: 0,
        }
    }

    fn begin(
        &mut self,
        role: AgentRole,
        planned: PlannedWork,
        elapsed_seconds: u64,
    ) -> Result<Admission, RuntimeEvent> {
        Self::check(
            role,
            BudgetDimension::WallTime,
            elapsed_seconds,
            self.limits.maximum_wall_time_seconds,
        )?;
        Self::check(
            role,
            BudgetDimension::Turns,
            self.usage.turns,
            self.limits.maximum_turns,
        )?;
        Self::check_capacity(
            role,
            BudgetDimension::ModelTokens,
            self.usage.model_tokens.saturating_add(self.reserved_tokens),
            planned.model_tokens,
            self.limits.maximum_model_tokens,
        )?;
        Self::check_capacity(
            role,
            BudgetDimension::Cost,
            self.usage.cost_microusd.saturating_add(self.reserved_cost),
            planned.cost_microusd,
            self.limits.maximum_cost_microusd,
        )?;
        if planned.experiment {
            Self::check(
                role,
                BudgetDimension::Experiments,
                u64::from(self.usage.experiments),
                u64::from(self.limits.maximum_experiments),
            )?;
        }
        Self::check(
            role,
            BudgetDimension::Concurrency,
            u64::from(self.usage.active_calls),
            u64::from(self.limits.maximum_concurrency),
        )?;

        self.usage.turns = self.usage.turns.saturating_add(1);
        self.usage.active_calls = self.usage.active_calls.saturating_add(1);
        self.reserved_tokens = self.reserved_tokens.saturating_add(planned.model_tokens);
        self.reserved_cost = self.reserved_cost.saturating_add(planned.cost_microusd);
        if planned.experiment {
            self.usage.experiments = self.usage.experiments.saturating_add(1);
        }
        Ok(Admission { role, planned })
    }

    fn finish(
        &mut self,
        admission: &Admission,
        usage: &TokenUsage,
        cost_microusd: u64,
    ) -> Option<RuntimeEvent> {
        self.usage.active_calls = self.usage.active_calls.saturating_sub(1);
        self.reserved_tokens = self
            .reserved_tokens
            .saturating_sub(admission.planned.model_tokens);
        self.reserved_cost = self
            .reserved_cost
            .saturating_sub(admission.planned.cost_microusd);
        self.usage.model_tokens = self.usage.model_tokens.saturating_add(usage.total_tokens);
        self.usage.cost_microusd = self.usage.cost_microusd.saturating_add(cost_microusd);
        if self.usage.model_tokens > self.limits.maximum_model_tokens {
            Some(exhausted(
                admission.role,
                BudgetDimension::ModelTokens,
                self.usage.model_tokens,
                self.limits.maximum_model_tokens,
            ))
        } else if self.usage.cost_microusd > self.limits.maximum_cost_microusd {
            Some(exhausted(
                admission.role,
                BudgetDimension::Cost,
                self.usage.cost_microusd,
                self.limits.maximum_cost_microusd,
            ))
        } else {
            None
        }
    }

    fn check(
        role: AgentRole,
        dimension: BudgetDimension,
        used: u64,
        limit: u64,
    ) -> Result<(), RuntimeEvent> {
        if used >= limit {
            let outcome = if dimension == BudgetDimension::Concurrency {
                BudgetOutcome::Deferred
            } else {
                BudgetOutcome::Inconclusive
            };
            Err(RuntimeEvent::BudgetExhausted {
                schema_version: SCHEMA_VERSION,
                role,
                dimension,
                used,
                limit,
                outcome,
            })
        } else {
            Ok(())
        }
    }

    fn check_capacity(
        role: AgentRole,
        dimension: BudgetDimension,
        used: u64,
        planned: u64,
        limit: u64,
    ) -> Result<(), RuntimeEvent> {
        let projected = used.saturating_add(planned);
        if projected > limit {
            Err(RuntimeEvent::BudgetExhausted {
                schema_version: SCHEMA_VERSION,
                role,
                dimension,
                used: projected,
                limit,
                outcome: BudgetOutcome::Inconclusive,
            })
        } else {
            Ok(())
        }
    }
}

fn exhausted(role: AgentRole, dimension: BudgetDimension, used: u64, limit: u64) -> RuntimeEvent {
    RuntimeEvent::BudgetExhausted {
        schema_version: SCHEMA_VERSION,
        role,
        dimension,
        used,
        limit,
        outcome: BudgetOutcome::Inconclusive,
    }
}

#[derive(Clone, Debug)]
pub struct RoleRun<T> {
    pub output: T,
    pub usage: TokenUsage,
    pub estimated_cost_microusd: u64,
    pub attempts: u8,
    pub events: Vec<RuntimeEvent>,
}

#[derive(Debug)]
pub struct AgentRuntime {
    provider: Arc<dyn ModelProvider>,
    model: String,
    configurations: BTreeMap<AgentRole, RoleConfiguration>,
    budget: Mutex<BudgetController>,
}

impl AgentRuntime {
    #[must_use]
    pub fn new(
        provider: Arc<dyn ModelProvider>,
        model: impl Into<String>,
        budget: RuntimeBudget,
    ) -> Self {
        Self {
            provider,
            model: model.into(),
            configurations: default_role_configurations(),
            budget: Mutex::new(BudgetController::new(budget)),
        }
    }

    #[must_use]
    pub fn configurations(&self) -> &BTreeMap<AgentRole, RoleConfiguration> {
        &self.configurations
    }

    /// Executes one typed role with bounded retries and explicit cancellation.
    ///
    /// # Errors
    /// Returns an error for context serialization/size, budget exhaustion,
    /// cancellation, provider failure, or invalid typed output.
    pub async fn execute<R: RoleContract>(
        &self,
        input: &R::Input,
        elapsed_seconds: u64,
        cancellation: &CancellationToken,
    ) -> Result<RoleRun<R::Output>, RuntimeError> {
        let configuration = self
            .configurations
            .get(&R::ROLE)
            .ok_or(RuntimeError::MissingRoleConfiguration(R::ROLE))?;
        let context = serde_json::to_string(input)?;
        if context.len() > configuration.maximum_context_bytes {
            return Err(RuntimeError::ContextTooLarge {
                actual: context.len(),
                limit: configuration.maximum_context_bytes,
            });
        }
        let planned = PlannedWork {
            model_tokens: u64::from(configuration.maximum_output_tokens)
                .saturating_add(u64::try_from(context.len() / 4).unwrap_or(u64::MAX)),
            cost_microusd: configuration.expected_cost_microusd,
            experiment: configuration.counts_as_experiment,
        };
        let request = ModelRequest {
            model: self.model.clone(),
            messages: vec![
                ModelMessage {
                    role: MessageRole::System,
                    content: configuration.system_instruction.clone(),
                },
                ModelMessage {
                    role: MessageRole::User,
                    content: context,
                },
            ],
            response_schema: R::response_schema(),
            max_output_tokens: configuration.maximum_output_tokens,
        };

        let mut attempts = 0_u8;
        loop {
            attempts = attempts.saturating_add(1);
            let admission = self
                .budget
                .lock()
                .map_err(|error| RuntimeError::Internal(error.to_string()))?
                .begin(R::ROLE, planned.clone(), elapsed_seconds)
                .map_err(RuntimeError::Budget)?;
            let response = tokio::select! {
                () = cancellation.cancelled() => Err(RuntimeError::Cancelled),
                result = self.provider.complete(&request) => result.map_err(RuntimeError::Provider),
            };
            match response {
                Ok(response) => {
                    let event = self
                        .budget
                        .lock()
                        .map_err(|error| RuntimeError::Internal(error.to_string()))?
                        .finish(
                            &admission,
                            &response.usage,
                            response.estimated_cost_microusd,
                        );
                    let output = serde_json::from_value(response.content)?;
                    return Ok(RoleRun {
                        output,
                        usage: response.usage,
                        estimated_cost_microusd: response.estimated_cost_microusd,
                        attempts,
                        events: event.into_iter().collect(),
                    });
                }
                Err(error) => {
                    let _ = self
                        .budget
                        .lock()
                        .map_err(|poison| RuntimeError::Internal(poison.to_string()))?
                        .finish(&admission, &TokenUsage::default(), 0);
                    if matches!(&error, RuntimeError::Provider(provider) if retryable(provider))
                        && attempts < configuration.maximum_attempts
                    {
                        continue;
                    }
                    return Err(error);
                }
            }
        }
    }

    /// Returns a deterministic resource-usage summary.
    ///
    /// # Errors
    /// Returns an error only if the internal budget mutex was poisoned.
    pub fn usage(&self) -> Result<RuntimeUsage, RuntimeError> {
        self.budget
            .lock()
            .map(|budget| budget.usage.clone())
            .map_err(|error| RuntimeError::Internal(error.to_string()))
    }
}

fn retryable(error: &ProviderError) -> bool {
    matches!(
        error,
        ProviderError::Timeout(_)
            | ProviderError::Transport(_)
            | ProviderError::Http {
                status: 429 | 500..=599,
                ..
            }
    )
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("role configuration is missing: {0:?}")]
    MissingRoleConfiguration(AgentRole),
    #[error("role context is too large: {actual} bytes exceeds {limit}")]
    ContextTooLarge { actual: usize, limit: usize },
    #[error("budget prevented role execution: {0:?}")]
    Budget(RuntimeEvent),
    #[error("role execution was cancelled")]
    Cancelled,
    #[error("model provider failed: {0}")]
    Provider(ProviderError),
    #[error("role JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("agent runtime internal state failed: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::{
        AgentRole, BudgetController, BudgetDimension, PlannedWork, RuntimeBudget, RuntimeEvent,
    };

    fn dimension(error: &RuntimeEvent) -> BudgetDimension {
        let RuntimeEvent::BudgetExhausted { dimension, .. } = error;
        *dimension
    }

    #[test]
    fn every_budget_dimension_fails_explicitly() {
        let role = AgentRole::Mapper;
        let work = PlannedWork {
            model_tokens: 2,
            cost_microusd: 2,
            experiment: false,
        };

        let mut turns = BudgetController::new(RuntimeBudget {
            maximum_turns: 0,
            ..RuntimeBudget::default()
        });
        assert_eq!(
            dimension(&turns.begin(role, work.clone(), 0).unwrap_err()),
            BudgetDimension::Turns
        );

        let mut wall_time = BudgetController::new(RuntimeBudget {
            maximum_wall_time_seconds: 1,
            ..RuntimeBudget::default()
        });
        assert_eq!(
            dimension(&wall_time.begin(role, work.clone(), 1).unwrap_err()),
            BudgetDimension::WallTime
        );

        let mut tokens = BudgetController::new(RuntimeBudget {
            maximum_model_tokens: 1,
            ..RuntimeBudget::default()
        });
        assert_eq!(
            dimension(&tokens.begin(role, work.clone(), 0).unwrap_err()),
            BudgetDimension::ModelTokens
        );

        let mut cost = BudgetController::new(RuntimeBudget {
            maximum_cost_microusd: 1,
            ..RuntimeBudget::default()
        });
        assert_eq!(
            dimension(&cost.begin(role, work.clone(), 0).unwrap_err()),
            BudgetDimension::Cost
        );

        let mut experiments = BudgetController::new(RuntimeBudget {
            maximum_experiments: 0,
            ..RuntimeBudget::default()
        });
        let experiment = PlannedWork {
            experiment: true,
            ..work.clone()
        };
        assert_eq!(
            dimension(&experiments.begin(role, experiment, 0).unwrap_err()),
            BudgetDimension::Experiments
        );

        let mut concurrency = BudgetController::new(RuntimeBudget {
            maximum_concurrency: 0,
            ..RuntimeBudget::default()
        });
        assert_eq!(
            dimension(&concurrency.begin(role, work, 0).unwrap_err()),
            BudgetDimension::Concurrency
        );
    }
}
