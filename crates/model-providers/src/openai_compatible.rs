use std::env;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{ModelProvider, ModelRequest, ModelResponse, ProviderError, SecretString, TokenUsage};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Pricing {
    pub input_microusd_per_million_tokens: u64,
    pub output_microusd_per_million_tokens: u64,
}

#[derive(Clone, Debug)]
pub struct OpenAiCompatibleConfig {
    pub endpoint: String,
    pub api_key_environment: String,
    pub timeout: Duration,
    pub maximum_retries: u8,
    pub initial_retry_delay: Duration,
    pub pricing: Pricing,
    pub application_name: Option<String>,
    pub application_url: Option<String>,
}

impl OpenAiCompatibleConfig {
    #[must_use]
    pub fn openrouter() -> Self {
        Self {
            endpoint: "https://openrouter.ai/api/v1/chat/completions".to_owned(),
            api_key_environment: "OPENROUTER_API_KEY".to_owned(),
            timeout: Duration::from_secs(60),
            maximum_retries: 2,
            initial_retry_delay: Duration::from_millis(250),
            pricing: Pricing::default(),
            application_name: Some("Evidence-Driven Security Agent".to_owned()),
            application_url: None,
        }
    }
}

#[derive(Debug)]
pub struct OpenAiCompatibleProvider {
    client: reqwest::Client,
    config: OpenAiCompatibleConfig,
    api_key: SecretString,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StructuredOutputMode {
    JsonSchema,
    JsonObject,
}

/// An environment-configured provider that applies its configured model to every request.
#[derive(Debug)]
pub struct ConfiguredProvider {
    provider: OpenAiCompatibleProvider,
    model: String,
}

impl ConfiguredProvider {
    /// Loads a generic OpenAI-compatible provider from `.env` and the host environment.
    ///
    /// Host values take precedence over `.env`. Required variables are `MODEL_API_KEY`,
    /// `MODEL_API_URL`, and `MODEL_NAME`. `MODEL_PROVIDER`, when set, must be
    /// `openai-compatible`.
    ///
    /// # Errors
    /// Returns a normalized configuration error for missing or malformed values.
    pub fn from_environment() -> Result<Self, ProviderError> {
        dotenvy::dotenv().ok();
        let provider_kind = optional_environment("MODEL_PROVIDER")
            .unwrap_or_else(|| "openai-compatible".to_owned());
        if provider_kind != "openai-compatible" {
            return Err(ProviderError::Configuration(format!(
                "unsupported MODEL_PROVIDER: {provider_kind}"
            )));
        }

        let endpoint = required_environment("MODEL_API_URL")?;
        let model = required_environment("MODEL_NAME")?;
        let api_key = SecretString::new(required_environment("MODEL_API_KEY")?);
        let timeout = Duration::from_secs(parse_environment("MODEL_TIMEOUT_SECONDS", 60_u64)?);
        let maximum_retries = parse_environment("MODEL_MAX_RETRIES", 2_u8)?;
        let input_price = parse_usd_price("MODEL_INPUT_COST_PER_MILLION_USD")?;
        let output_price = parse_usd_price("MODEL_OUTPUT_COST_PER_MILLION_USD")?;
        let provider = OpenAiCompatibleProvider::new(
            OpenAiCompatibleConfig {
                endpoint,
                api_key_environment: "MODEL_API_KEY".to_owned(),
                timeout,
                maximum_retries,
                initial_retry_delay: Duration::from_millis(250),
                pricing: Pricing {
                    input_microusd_per_million_tokens: input_price,
                    output_microusd_per_million_tokens: output_price,
                },
                application_name: Some("Evidence-Driven Security Agent".to_owned()),
                application_url: None,
            },
            api_key,
        )?;
        Ok(Self { provider, model })
    }

    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }
}

#[async_trait]
impl ModelProvider for ConfiguredProvider {
    async fn complete(&self, request: &ModelRequest) -> Result<ModelResponse, ProviderError> {
        let mut configured_request = request.clone();
        configured_request.model.clone_from(&self.model);
        self.provider.complete(&configured_request).await
    }
}

impl OpenAiCompatibleProvider {
    /// Builds an adapter using a host environment variable for the API key.
    ///
    /// # Errors
    /// Returns an error when the environment variable is absent or HTTP configuration is invalid.
    pub fn from_environment(config: OpenAiCompatibleConfig) -> Result<Self, ProviderError> {
        let api_key = env::var(&config.api_key_environment)
            .map_err(|_| ProviderError::MissingEnvironment(config.api_key_environment.clone()))?;
        Self::new(config, SecretString::new(api_key))
    }

    /// Builds an adapter with an explicitly supplied, redacting secret.
    ///
    /// # Errors
    /// Returns an error for an empty key, endpoint, or invalid HTTP configuration.
    pub fn new(
        config: OpenAiCompatibleConfig,
        api_key: SecretString,
    ) -> Result<Self, ProviderError> {
        if config.endpoint.trim().is_empty() {
            return Err(ProviderError::Configuration("endpoint is empty".to_owned()));
        }
        if api_key.expose().is_empty() {
            return Err(ProviderError::Configuration("API key is empty".to_owned()));
        }
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|error| ProviderError::Configuration(error.to_string()))?;
        Ok(Self {
            client,
            config,
            api_key,
        })
    }

    async fn attempt(
        &self,
        request: &ModelRequest,
        output_mode: StructuredOutputMode,
    ) -> Result<ModelResponse, ProviderError> {
        let mut headers = HeaderMap::new();
        let authorization = format!("Bearer {}", self.api_key.expose());
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&authorization)
                .map_err(|error| ProviderError::Configuration(error.to_string()))?,
        );
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(name) = &self.config.application_name {
            headers.insert(
                "X-Title",
                HeaderValue::from_str(name)
                    .map_err(|error| ProviderError::Configuration(error.to_string()))?,
            );
        }
        if let Some(url) = &self.config.application_url {
            headers.insert(
                "HTTP-Referer",
                HeaderValue::from_str(url)
                    .map_err(|error| ProviderError::Configuration(error.to_string()))?,
            );
        }

        let body = request_body(request, output_mode);
        let response = tokio::time::timeout(
            self.config.timeout,
            self.client
                .post(&self.config.endpoint)
                .headers(headers)
                .json(&body)
                .send(),
        )
        .await
        .map_err(|_| ProviderError::Timeout(self.config.timeout))?
        .map_err(|error| {
            if error.is_timeout() {
                ProviderError::Timeout(self.config.timeout)
            } else {
                ProviderError::Transport(self.api_key.redact(&error.to_string()))
            }
        })?;

        let status = response.status();
        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let text = response
            .text()
            .await
            .map_err(|error| ProviderError::Transport(self.api_key.redact(&error.to_string())))?;
        if !status.is_success() {
            return Err(ProviderError::Http {
                status: status.as_u16(),
                message: self.api_key.redact(&text),
            });
        }

        let envelope: ChatCompletion = serde_json::from_str(&text).map_err(|error| {
            ProviderError::MalformedJson(self.api_key.redact(&error.to_string()))
        })?;
        let content = envelope
            .choices
            .first()
            .ok_or_else(|| ProviderError::MalformedJson("choices is empty".to_owned()))?
            .message
            .content
            .as_structured()?;
        validate_schema(&request.response_schema, &content)?;
        let usage = envelope.usage.unwrap_or_default().into();
        let estimated_cost_microusd = self.config.pricing.estimate(&usage);
        Ok(ModelResponse {
            content,
            usage,
            estimated_cost_microusd,
            provider_request_id: request_id,
        })
    }
}

#[async_trait]
impl ModelProvider for OpenAiCompatibleProvider {
    async fn complete(&self, request: &ModelRequest) -> Result<ModelResponse, ProviderError> {
        let mut retry_delay = self.config.initial_retry_delay;
        let mut retries = 0;
        let mut output_mode = StructuredOutputMode::JsonSchema;
        loop {
            match self.attempt(request, output_mode).await {
                Ok(response) => return Ok(response),
                Err(error)
                    if output_mode == StructuredOutputMode::JsonSchema
                        && json_schema_format_unavailable(&error) =>
                {
                    output_mode = StructuredOutputMode::JsonObject;
                }
                Err(error) if retryable(&error) && retries < self.config.maximum_retries => {
                    retries += 1;
                    tokio::time::sleep(retry_delay).await;
                    retry_delay = retry_delay.saturating_mul(2);
                }
                Err(error) => return Err(error),
            }
        }
    }
}

impl Pricing {
    fn estimate(self, usage: &TokenUsage) -> u64 {
        let input = u128::from(usage.input_tokens)
            .saturating_mul(u128::from(self.input_microusd_per_million_tokens));
        let output = u128::from(usage.output_tokens)
            .saturating_mul(u128::from(self.output_microusd_per_million_tokens));
        u64::try_from((input + output) / 1_000_000).unwrap_or(u64::MAX)
    }
}

fn required_environment(name: &str) -> Result<String, ProviderError> {
    optional_environment(name).ok_or_else(|| ProviderError::MissingEnvironment(name.to_owned()))
}

fn optional_environment(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn parse_environment<T>(name: &str, default: T) -> Result<T, ProviderError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    optional_environment(name).map_or(Ok(default), |value| {
        value.parse().map_err(|error| {
            ProviderError::Configuration(format!("{name} has an invalid value: {error}"))
        })
    })
}

fn parse_usd_price(name: &str) -> Result<u64, ProviderError> {
    let Some(value) = optional_environment(name) else {
        return Ok(0);
    };
    let dollars: f64 = value.parse().map_err(|error| {
        ProviderError::Configuration(format!("{name} has an invalid value: {error}"))
    })?;
    if !dollars.is_finite() || dollars.is_sign_negative() {
        return Err(ProviderError::Configuration(format!(
            "{name} must be a finite non-negative number"
        )));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let microusd = (dollars * 1_000_000.0).round() as u64;
    Ok(microusd)
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

fn request_body(request: &ModelRequest, output_mode: StructuredOutputMode) -> Value {
    let mut messages = json!(request.messages);
    let response_format = match output_mode {
        StructuredOutputMode::JsonSchema => json!({
            "type": "json_schema",
            "json_schema": {
                "name": "edsa_structured_response",
                "strict": true,
                "schema": request.response_schema
            }
        }),
        StructuredOutputMode::JsonObject => {
            if let Value::Array(items) = &mut messages {
                items.insert(
                    0,
                    json!({
                        "role": "system",
                        "content": format!(
                            "Return only a JSON object matching this JSON Schema: {}",
                            request.response_schema
                        )
                    }),
                );
            }
            json!({ "type": "json_object" })
        }
    };
    json!({
        "model": request.model,
        "messages": messages,
        "max_tokens": request.max_output_tokens,
        "response_format": response_format
    })
}

fn json_schema_format_unavailable(error: &ProviderError) -> bool {
    matches!(
        error,
        ProviderError::Http { status: 400, message }
            if message.to_ascii_lowercase().contains("response_format")
                && message.to_ascii_lowercase().contains("unavailable")
    )
}

fn validate_schema(schema: &Value, instance: &Value) -> Result<(), ProviderError> {
    let validator = jsonschema::validator_for(schema).map_err(|error| {
        ProviderError::Configuration(format!("invalid response schema: {error}"))
    })?;
    if let Err(error) = validator.validate(instance) {
        return Err(ProviderError::SchemaValidation(error.to_string()));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct ChatCompletion {
    choices: Vec<Choice>,
    usage: Option<ApiUsage>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: AssistantMessage,
}

#[derive(Debug, Deserialize)]
struct AssistantMessage {
    content: StructuredContent,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum StructuredContent {
    Text(String),
    Json(Value),
}

impl StructuredContent {
    fn as_structured(&self) -> Result<Value, ProviderError> {
        match self {
            Self::Text(text) => parse_first_json_value(text),
            Self::Json(value) => Ok(value.clone()),
        }
    }
}

fn parse_first_json_value(text: &str) -> Result<Value, ProviderError> {
    let trimmed = text.trim();
    let mut values = serde_json::Deserializer::from_str(trimmed).into_iter::<Value>();
    let value = values
        .next()
        .ok_or_else(|| ProviderError::MalformedJson("response content is empty".to_owned()))?
        .map_err(|error| ProviderError::MalformedJson(error.to_string()))?;
    let remainder = trimmed[values.byte_offset()..].trim();

    // Some OpenAI-compatible providers append a short explanation even when
    // JSON mode is requested. It is not part of the typed response and is
    // therefore ignored. A second JSON value is ambiguous and remains an error.
    let contains_second_value = serde_json::Deserializer::from_str(remainder)
        .into_iter::<Value>()
        .next()
        .is_some_and(|candidate| candidate.is_ok());
    if contains_second_value {
        return Err(ProviderError::MalformedJson(
            "response content contains more than one JSON value".to_owned(),
        ));
    }
    Ok(value)
}

#[derive(Debug, Default, Deserialize)]
struct ApiUsage {
    #[serde(default, rename = "prompt_tokens", alias = "input_tokens")]
    prompt: u64,
    #[serde(default, rename = "completion_tokens", alias = "output_tokens")]
    completion: u64,
    #[serde(default, rename = "total_tokens")]
    total: u64,
}

impl From<ApiUsage> for TokenUsage {
    fn from(value: ApiUsage) -> Self {
        Self {
            input_tokens: value.prompt,
            output_tokens: value.completion,
            total_tokens: value.total,
        }
    }
}
