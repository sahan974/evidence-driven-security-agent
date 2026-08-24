use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::{ModelProvider, ModelRequest, ModelResponse, ProviderError};

#[derive(Debug, Default)]
pub struct MockProvider {
    responses: Mutex<VecDeque<Result<ModelResponse, ProviderError>>>,
}

impl MockProvider {
    #[must_use]
    pub fn with_responses(responses: Vec<Result<ModelResponse, ProviderError>>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
        }
    }

    /// Adds a response to the deterministic response queue.
    ///
    /// # Panics
    /// Panics only if another thread poisoned the queue mutex.
    pub fn push(&self, response: Result<ModelResponse, ProviderError>) {
        self.responses
            .lock()
            .expect("mock queue poisoned")
            .push_back(response);
    }
}

#[async_trait]
impl ModelProvider for MockProvider {
    async fn complete(&self, _request: &ModelRequest) -> Result<ModelResponse, ProviderError> {
        self.responses
            .lock()
            .map_err(|error| ProviderError::Transport(error.to_string()))?
            .pop_front()
            .unwrap_or(Err(ProviderError::MockExhausted))
    }
}
