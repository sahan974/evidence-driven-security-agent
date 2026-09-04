use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use edsa_model_providers::{
    ConfiguredProvider, MessageRole, ModelMessage, ModelProvider, ModelRequest,
    OpenAiCompatibleConfig, OpenAiCompatibleProvider, Pricing, ProviderError, SecretString,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn request() -> ModelRequest {
    ModelRequest {
        model: "deepseek/deepseek-chat".to_owned(),
        messages: vec![ModelMessage {
            role: MessageRole::User,
            content: "Return a hypothesis".to_owned(),
        }],
        response_schema: json!({
            "type": "object",
            "required": ["hypothesis"],
            "additionalProperties": false,
            "properties": { "hypothesis": { "type": "string" } }
        }),
        max_output_tokens: 200,
    }
}

fn provider(
    endpoint: String,
    timeout: Duration,
    retries: u8,
    key: &str,
) -> OpenAiCompatibleProvider {
    OpenAiCompatibleProvider::new(
        OpenAiCompatibleConfig {
            endpoint,
            api_key_environment: "UNUSED_TEST_KEY".to_owned(),
            timeout,
            maximum_retries: retries,
            initial_retry_delay: Duration::from_millis(1),
            pricing: Pricing {
                input_microusd_per_million_tokens: 100_000,
                output_microusd_per_million_tokens: 200_000,
            },
            application_name: None,
            application_url: None,
        },
        SecretString::new(key),
    )
    .unwrap()
}

async fn server(
    status: u16,
    body: String,
    delay: Duration,
) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let request_count = Arc::clone(&requests);
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            request_count.fetch_add(1, Ordering::SeqCst);
            let mut buffer = vec![0_u8; 16 * 1024];
            let _ = socket.read(&mut buffer).await;
            tokio::time::sleep(delay).await;
            let reason = if status == 200 { "OK" } else { "Error" };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });
    (
        format!("http://{address}/chat/completions"),
        requests,
        handle,
    )
}

fn success_body(content: &str) -> String {
    json!({
        "choices": [{ "message": { "content": content } }],
        "usage": { "prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15 }
    })
    .to_string()
}

#[tokio::test]
async fn validates_structured_response_and_reports_usage() {
    let (endpoint, _, server) = server(
        200,
        success_body(r#"{"hypothesis":"path traversal"}"#),
        Duration::ZERO,
    )
    .await;
    let response = provider(endpoint, Duration::from_secs(1), 0, "test-secret")
        .complete(&request())
        .await
        .unwrap();
    assert_eq!(response.content, json!({"hypothesis": "path traversal"}));
    assert_eq!(response.usage.total_tokens, 15);
    assert_eq!(response.estimated_cost_microusd, 2);
    server.abort();
}

#[tokio::test]
async fn accepts_one_schema_valid_json_value_with_trailing_provider_commentary() {
    let (endpoint, _, server) = server(
        200,
        success_body(
            "{\"hypothesis\":\"path traversal\"}\nThe requested structured response is above.",
        ),
        Duration::ZERO,
    )
    .await;
    let response = provider(endpoint, Duration::from_secs(1), 0, "test-secret")
        .complete(&request())
        .await
        .unwrap();
    assert_eq!(response.content, json!({"hypothesis": "path traversal"}));
    server.abort();
}

#[tokio::test]
async fn rejects_ambiguous_multiple_json_values() {
    let (endpoint, _, server) = server(
        200,
        success_body("{\"hypothesis\":\"first\"}\n{\"hypothesis\":\"second\"}"),
        Duration::ZERO,
    )
    .await;
    let error = provider(endpoint, Duration::from_secs(1), 0, "test-secret")
        .complete(&request())
        .await
        .unwrap_err();
    assert!(matches!(error, ProviderError::MalformedJson(_)));
    server.abort();
}

#[tokio::test]
async fn timeout_is_normalized() {
    let (endpoint, _, server) = server(200, success_body("{}"), Duration::from_millis(200)).await;
    let error = provider(endpoint, Duration::from_millis(20), 0, "test-secret")
        .complete(&request())
        .await
        .unwrap_err();
    assert!(matches!(error, ProviderError::Timeout(_)));
    server.abort();
}

#[tokio::test]
async fn malformed_json_is_rejected() {
    let (endpoint, _, server) = server(200, "not-json".to_owned(), Duration::ZERO).await;
    let error = provider(endpoint, Duration::from_secs(1), 0, "test-secret")
        .complete(&request())
        .await
        .unwrap_err();
    assert!(matches!(error, ProviderError::MalformedJson(_)));
    server.abort();
}

#[tokio::test]
async fn retries_exhaust_on_transient_status() {
    let (endpoint, requests, server) = server(503, "busy".to_owned(), Duration::ZERO).await;
    let error = provider(endpoint, Duration::from_secs(1), 2, "test-secret")
        .complete(&request())
        .await
        .unwrap_err();
    assert!(matches!(error, ProviderError::Http { status: 503, .. }));
    assert_eq!(requests.load(Ordering::SeqCst), 3);
    server.abort();
}

#[tokio::test]
async fn cancellation_drops_in_flight_request() {
    let (endpoint, _, server) = server(200, success_body("{}"), Duration::from_secs(5)).await;
    let provider = Arc::new(provider(
        endpoint,
        Duration::from_secs(10),
        0,
        "test-secret",
    ));
    let task = tokio::spawn({
        let provider = Arc::clone(&provider);
        async move { provider.complete(&request()).await }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    server.abort();
}

#[tokio::test]
async fn secrets_are_redacted_from_errors_and_debug() {
    let secret = "super-secret-api-key";
    let (endpoint, _, server) = server(401, format!("invalid key: {secret}"), Duration::ZERO).await;
    let provider = provider(endpoint, Duration::from_secs(1), 0, secret);
    let debug = format!("{provider:?}");
    let error = provider.complete(&request()).await.unwrap_err();
    let message = error.to_string();
    assert!(!debug.contains(secret));
    assert!(!message.contains(secret));
    assert!(message.contains("[REDACTED]"));
    server.abort();
}

#[tokio::test]
async fn schema_mismatch_is_rejected() {
    let (endpoint, _, server) =
        server(200, success_body(r#"{"hypothesis":42}"#), Duration::ZERO).await;
    let error = provider(endpoint, Duration::from_secs(1), 0, "test-secret")
        .complete(&request())
        .await
        .unwrap_err();
    assert!(matches!(error, ProviderError::SchemaValidation(_)));
    server.abort();
}

#[tokio::test]
#[ignore = "requires generic MODEL_* configuration and may incur a live API cost"]
async fn configured_provider_live_smoke_test() {
    let provider = ConfiguredProvider::from_environment()
        .expect("generic MODEL_* variables must be configured");
    let response = provider.complete(&request()).await.unwrap();
    assert!(response.content.get("hypothesis").is_some());
}
