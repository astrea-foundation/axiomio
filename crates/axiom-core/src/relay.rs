//! Client for the Axiom backend relay (`/relay/*`). Sends ciphertext + keys with the user's API
//! key and parses the SSE event vocabulary defined in backend `relay/service.py`.

use std::pin::Pin;

use async_trait::async_trait;
use eventsource_stream::Eventsource;
use futures_util::{Stream, StreamExt};
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};

fn default_provider() -> String {
    "near".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct RelayModel {
    pub id: String,
    pub label: String,
    pub short_label: String,
    pub model: String,
    pub base_url: String,
    // Defaults so the proxy keeps working against backends that predate the provider field.
    #[serde(default = "default_provider")]
    pub provider: String,
    #[serde(default)]
    pub supported_reasoning_efforts: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayMessage {
    pub role: String,
    pub encrypted_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_reasoning_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_refusal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_tool_calls: Option<Vec<RelayEncryptedToolCall>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayEncryptedTool {
    #[serde(rename = "type")]
    pub kind: String,
    pub function: RelayEncryptedFunctionDefinition,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayEncryptedFunctionDefinition {
    pub encrypted_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_description: Option<String>,
    pub encrypted_parameters: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strict: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum RelayEncryptedToolChoice {
    Mode(String),
    Named(RelayEncryptedNamedToolChoice),
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayEncryptedNamedToolChoice {
    #[serde(rename = "type")]
    pub kind: String,
    pub function: RelayEncryptedNamedFunction,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayEncryptedNamedFunction {
    pub encrypted_name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RelayEncryptedToolCall {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub function: RelayEncryptedFunctionCall,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RelayEncryptedFunctionCall {
    pub encrypted_name: String,
    pub encrypted_arguments: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RelayEncryptedToolCallDelta {
    pub index: u32,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    #[serde(default)]
    pub function: Option<RelayEncryptedFunctionCallDelta>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RelayEncryptedFunctionCallDelta {
    #[serde(default)]
    pub encrypted_name: Option<String>,
    #[serde(default)]
    pub encrypted_arguments: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayChatRequest {
    pub model_id: String,
    pub encryption_version: u8,
    /// E2EE protocol id (e.g. "near-v2"). Optional so the request stays compatible with
    /// backends that predate multi-provider support.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e2ee_protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_public_key_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_public_key_hex: Option<String>,
    pub encrypted_messages: Vec<RelayMessage>,
    pub encrypt_all_fields: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_tools: Option<Vec<RelayEncryptedTool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_tool_choice: Option<RelayEncryptedToolChoice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallel_tool_calls: Option<bool>,
    pub stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampling: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_format: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RelayUsage {
    #[serde(default)]
    pub prompt_tokens: Option<u32>,
    #[serde(default)]
    pub completion_tokens: Option<u32>,
    #[serde(default)]
    pub total_tokens: Option<u32>,
}

/// One event from a relay stream, already mapped off the SSE wire vocabulary.
#[derive(Debug, Clone)]
pub enum RelayEvent {
    Delta {
        content: Option<String>,
        reasoning: Option<String>,
        refusal: Option<String>,
        tool_calls: Vec<RelayEncryptedToolCallDelta>,
        sequence: u64,
    },
    Completed {
        usage: RelayUsage,
        finish_reason: Option<String>,
    },
    Cancelled {
        reason: Option<String>,
    },
    Failed {
        error: String,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct RelayCompletion {
    pub id: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub encrypted_content: Option<String>,
    #[serde(default)]
    pub encrypted_reasoning_content: Option<String>,
    #[serde(default)]
    pub encrypted_refusal: Option<String>,
    #[serde(default)]
    pub encrypted_tool_calls: Vec<RelayEncryptedToolCall>,
    #[serde(default)]
    pub finish_reason: Option<String>,
    #[serde(default)]
    pub usage: RelayUsage,
}

#[derive(Deserialize)]
struct RelayDeltaPayload {
    #[serde(default)]
    encrypted_delta: Option<String>,
    #[serde(default)]
    encrypted_reasoning_delta: Option<String>,
    #[serde(default)]
    encrypted_refusal_delta: Option<String>,
    #[serde(default)]
    encrypted_tool_calls: Vec<RelayEncryptedToolCallDelta>,
    sequence: u64,
}

#[derive(Deserialize)]
struct RelayCompletedPayload {
    usage: RelayUsage,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct RelayCancelledPayload {
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize)]
struct RelayFailedPayload {
    error: String,
}

pub type RelayStream = Pin<Box<dyn Stream<Item = Result<RelayEvent>> + Send>>;

/// Abstraction over the backend relay so the server can be tested with a fake. `#[async_trait]`
/// makes it dyn-compatible for `Arc<dyn RelayApi>`.
#[async_trait]
pub trait RelayApi: Send + Sync {
    async fn list_models(&self, api_key: &str) -> Result<Vec<RelayModel>>;
    async fn complete(&self, api_key: &str, req: &RelayChatRequest) -> Result<RelayCompletion>;
    async fn stream(&self, api_key: &str, req: &RelayChatRequest) -> Result<RelayStream>;
}

pub struct HttpRelay {
    client: reqwest::Client,
    base_url: String,
}

impl HttpRelay {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api/v1{}", self.base_url, path)
    }

    async fn error_for_status(resp: reqwest::Response) -> CoreError {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        CoreError::Relay(format!("{status}: {body}"))
    }
}

/// Map a backend SSE event `(event_name, data_json)` to a RelayEvent.
fn map_event(name: &str, data: &str) -> Option<Result<RelayEvent>> {
    match name {
        "message.encrypted_delta" => Some(
            serde_json::from_str::<RelayDeltaPayload>(data)
                .map(|payload| RelayEvent::Delta {
                    content: payload.encrypted_delta,
                    reasoning: payload.encrypted_reasoning_delta,
                    refusal: payload.encrypted_refusal_delta,
                    tool_calls: payload.encrypted_tool_calls,
                    sequence: payload.sequence,
                })
                .map_err(|error| {
                    CoreError::Relay(format!("invalid encrypted delta event: {error}"))
                }),
        ),
        "message.encrypted_completed" => Some(
            serde_json::from_str::<RelayCompletedPayload>(data)
                .map(|payload| RelayEvent::Completed {
                    usage: payload.usage,
                    finish_reason: payload.finish_reason,
                })
                .map_err(|error| {
                    CoreError::Relay(format!("invalid encrypted completed event: {error}"))
                }),
        ),
        "run.created" | "run.completed" => None,
        "run.cancelled" => Some(
            serde_json::from_str::<RelayCancelledPayload>(data)
                .map(|payload| RelayEvent::Cancelled {
                    reason: payload.reason,
                })
                .map_err(|error| CoreError::Relay(format!("invalid cancelled event: {error}"))),
        ),
        "run.failed" => Some(
            serde_json::from_str::<RelayFailedPayload>(data)
                .map(|payload| RelayEvent::Failed {
                    error: payload.error,
                })
                .map_err(|error| CoreError::Relay(format!("invalid failed event: {error}"))),
        ),
        _ => Some(Err(CoreError::Relay(format!(
            "unexpected relay event: {name}"
        )))),
    }
}

#[async_trait]
impl RelayApi for HttpRelay {
    async fn list_models(&self, api_key: &str) -> Result<Vec<RelayModel>> {
        let resp = self
            .client
            .get(self.url("/relay/models"))
            .bearer_auth(api_key)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(Self::error_for_status(resp).await);
        }
        Ok(resp.json().await?)
    }

    async fn complete(&self, api_key: &str, req: &RelayChatRequest) -> Result<RelayCompletion> {
        let resp = self
            .client
            .post(self.url("/relay/chat/completions"))
            .bearer_auth(api_key)
            .json(req)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(Self::error_for_status(resp).await);
        }
        Ok(resp.json().await?)
    }

    async fn stream(&self, api_key: &str, req: &RelayChatRequest) -> Result<RelayStream> {
        let resp = self
            .client
            .post(self.url("/relay/chat/completions"))
            .bearer_auth(api_key)
            .json(req)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(Self::error_for_status(resp).await);
        }
        let events = resp
            .bytes_stream()
            .eventsource()
            .filter_map(|event| async move {
                match event {
                    Ok(ev) => map_event(&ev.event, &ev.data),
                    Err(e) => Some(Err(CoreError::Relay(e.to_string()))),
                }
            });
        Ok(Box::pin(events))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_delta_mapping_is_typed_and_fail_closed() {
        let valid = serde_json::json!({
            "encrypted_delta": null,
            "encrypted_tool_calls": [{
                "index": 0,
                "id": "call_1",
                "type": "function",
                "function": {
                    "encrypted_name": "ab",
                    "encrypted_arguments": "cd"
                }
            }],
            "sequence": 1
        });
        assert!(matches!(
            map_event("message.encrypted_delta", &valid.to_string()),
            Some(Ok(RelayEvent::Delta { tool_calls, sequence: 1, .. }))
                if tool_calls.len() == 1
        ));

        for malformed in [
            serde_json::json!({"encrypted_delta": {}, "sequence": 1}),
            serde_json::json!({
                "encrypted_tool_calls": [{
                    "index": 0,
                    "function": {"encrypted_name": 7}
                }],
                "sequence": 1
            }),
            serde_json::json!({"encrypted_delta": null}),
        ] {
            assert!(matches!(
                map_event("message.encrypted_delta", &malformed.to_string()),
                Some(Err(_))
            ));
        }
    }

    #[test]
    fn relay_completed_mapping_rejects_malformed_usage() {
        assert!(matches!(
            map_event(
                "message.encrypted_completed",
                r#"{"usage":{"prompt_tokens":"not-a-number"},"finish_reason":"stop"}"#,
            ),
            Some(Err(_))
        ));
        assert!(matches!(map_event("unexpected.event", "{}"), Some(Err(_))));
    }
}
