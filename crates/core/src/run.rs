use std::collections::BTreeSet;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Language, RepositorySnapshot, SCHEMA_VERSION};

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RunId(String);

impl RunId {
    #[must_use]
    pub fn generate(repository_digest: &str) -> Self {
        let timestamp = unix_time_milliseconds();
        let mut hasher = Sha256::new();
        hasher.update(repository_digest.as_bytes());
        hasher.update(timestamp.to_le_bytes());
        hasher.update(process::id().to_le_bytes());
        let digest = format!("{:x}", hasher.finalize());
        Self(format!("run-{timestamp}-{}", &digest[..12]))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunBudget {
    pub maximum_model_tokens: u64,
    pub maximum_cost_microusd: u64,
    pub maximum_turns: u32,
    pub maximum_experiments: u32,
    pub maximum_wall_time_seconds: u64,
}

impl RunBudget {
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.maximum_model_tokens > 0
            && self.maximum_cost_microusd > 0
            && self.maximum_turns > 0
            && self.maximum_experiments > 0
            && self.maximum_wall_time_seconds > 0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Approval {
    DirtyRepository,
    Network,
    DependencyInstallation,
    PatchApplication,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunApprovals {
    pub granted: BTreeSet<Approval>,
}

impl RunApprovals {
    pub fn grant(&mut self, approval: Approval) -> bool {
        self.granted.insert(approval)
    }

    #[must_use]
    pub fn contains(&self, approval: Approval) -> bool {
        self.granted.contains(&approval)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderMetadata {
    pub provider: String,
    pub model: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OptionalTool {
    pub name: String,
    pub executable: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DirtyTreeDecision {
    Clean,
    ExplicitlyAllowed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunConfiguration {
    pub schema_version: u16,
    pub run_id: RunId,
    pub created_at_unix_ms: u64,
    pub repository: RepositorySnapshot,
    pub provider: ProviderMetadata,
    pub budget: RunBudget,
    pub approvals: RunApprovals,
    pub dirty_tree_decision: DirtyTreeDecision,
    pub detected_languages: BTreeSet<Language>,
    pub enabled_optional_tools: Vec<OptionalTool>,
}

impl RunConfiguration {
    #[must_use]
    pub fn new(
        repository: RepositorySnapshot,
        provider: ProviderMetadata,
        budget: RunBudget,
        approvals: RunApprovals,
        dirty_tree_decision: DirtyTreeDecision,
        detected_languages: BTreeSet<Language>,
        mut enabled_optional_tools: Vec<OptionalTool>,
    ) -> Self {
        enabled_optional_tools.sort_by(|left, right| left.name.cmp(&right.name));
        Self {
            schema_version: SCHEMA_VERSION,
            run_id: RunId::generate(&repository.content_digest),
            created_at_unix_ms: unix_time_milliseconds(),
            repository,
            provider,
            budget,
            approvals,
            dirty_tree_decision,
            detected_languages,
            enabled_optional_tools,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Created,
    Ready,
    Running,
    Completed,
    Inconclusive,
    Cancelled,
    TimedOut,
    Failed,
}

impl RunStatus {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Inconclusive | Self::Cancelled | Self::TimedOut | Self::Failed
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunEvent {
    pub schema_version: u16,
    pub sequence: u64,
    pub recorded_at_unix_ms: u64,
    pub status: RunStatus,
    pub message: String,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub payload: serde_json::Value,
}

impl RunEvent {
    #[must_use]
    pub fn new(sequence: u64, status: RunStatus, message: impl Into<String>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            sequence,
            recorded_at_unix_ms: unix_time_milliseconds(),
            status,
            message: message.into(),
            payload: serde_json::Value::Null,
        }
    }

    #[must_use]
    pub fn with_payload(mut self, payload: serde_json::Value) -> Self {
        self.payload = payload;
        self
    }
}

#[must_use]
pub fn unix_time_milliseconds() -> u64 {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(milliseconds).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::RunBudget;

    #[test]
    fn every_budget_dimension_must_be_positive() {
        let valid = RunBudget {
            maximum_model_tokens: 1,
            maximum_cost_microusd: 1,
            maximum_turns: 1,
            maximum_experiments: 1,
            maximum_wall_time_seconds: 1,
        };
        assert!(valid.is_valid());

        let mut invalid = valid;
        invalid.maximum_turns = 0;
        assert!(!invalid.is_valid());
    }
}
