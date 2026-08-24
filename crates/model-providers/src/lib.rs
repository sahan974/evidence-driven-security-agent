//! Vendor-neutral model-provider contracts.
//!
//! Provider responses are validated JSON proposals. They cannot directly change
//! investigation verdicts or patch verification state.

pub mod mock;
pub mod openai_compatible;

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub use mock::MockProvider;
pub use openai_compatible::{
    ConfiguredProvider, OpenAiCompatibleConfig, OpenAiCompatibleProvider, Pricing,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageRole {
    System,
    User,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModelMessage {
    pub role: MessageRole,
    pub content: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ModelRequest {
    pub model: String,
    pub messages: Vec<ModelMessage>,
    pub response_schema: Value,
    pub max_output_tokens: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ModelResponse {
    pub content: Value,
    pub usage: TokenUsage,
    pub estimated_cost_microusd: u64,
    pub provider_request_id: Option<String>,
}

/// An API credential that redacts itself and cannot be serialized.
#[derive(Clone)]
pub struct SecretString(String);

impl SecretString {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }

    pub(crate) fn redact(&self, text: &str) -> String {
        if self.0.is_empty() {
            text.to_owned()
        } else {
            text.replace(&self.0, "[REDACTED]")
        }
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

#[async_trait]
pub trait ModelProvider: fmt::Debug + Send + Sync {
    /// Returns a schema-validated structured response.
    ///
    /// # Errors
    /// Returns a normalized [`ProviderError`] for configuration, transport,
    /// timeout, HTTP, decoding, or schema-validation failures.
    async fn complete(&self, request: &ModelRequest) -> Result<ModelResponse, ProviderError>;
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderError {
    #[error("required environment variable is missing: {0}")]
    MissingEnvironment(String),
    #[error("invalid provider configuration: {0}")]
    Configuration(String),
    #[error("provider request timed out after {0:?}")]
    Timeout(Duration),
    #[error("provider transport failed: {0}")]
    Transport(String),
    #[error("provider returned HTTP {status}: {message}")]
    Http { status: u16, message: String },
    #[error("provider returned malformed JSON: {0}")]
    MalformedJson(String),
    #[error("provider response failed schema validation: {0}")]
    SchemaValidation(String),
    #[error("mock provider has no queued response")]
    MockExhausted,
}
