//! End-to-end local proxy tests with a fake encrypted relay.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axiom_core::e2ee::{encrypt_to_model, ClientKeypair};
use axiom_core::error::{CoreError, Result};
use axiom_core::events::{RequestLogEntry, RequestTerminalStatus};
use axiom_core::relay::{
    RelayApi, RelayChatRequest, RelayCompletion, RelayEncryptedFunctionCall,
    RelayEncryptedFunctionCallDelta, RelayEncryptedToolCall, RelayEncryptedToolCallDelta,
    RelayEncryptedToolChoice, RelayEvent, RelayModel, RelayStream, RelayUsage,
};
use axiom_server::{bind, serve, ProxyCore};
use futures_util::{stream, StreamExt};
use serde_json::json;
use tokio_util::sync::CancellationToken;

const TOOL_NAME: &str = "read_secret";
const TOOL_DESCRIPTION: &str = "Read the sentinel file from the workspace";
const USER_PROMPT: &str = "Use read_secret on target.txt";
const TOOL_ARGUMENTS: &str = "{\"filePath\":\"target.txt\"}";
const TOOL_ARGUMENTS_2: &str = "{\"filePath\":\"other.txt\"}";
const TOOL_RESULT: &str = "TOKEN=before\n";
const TOOL_RESULT_2: &str = "TOKEN=other\n";
const MESSAGE_NAME: &str = "operator_secret";
const REFUSAL_HISTORY: &str = "encrypted refusal history";

fn hex32(value: &str) -> [u8; 32] {
    let bytes = hex::decode(value).unwrap();
    let mut output = [0u8; 32];
    output.copy_from_slice(&bytes);
    output
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FakeMode {
    Text,
    Tools,
    ToolsOpenAfterCompleted,
    TamperedTool,
    Fail402,
    StreamCancelled,
    StreamFailed,
    StreamEnds,
    StreamPending,
}

struct FakeRelay {
    mode: FakeMode,
    model_keypair: ClientKeypair,
    calls: AtomicUsize,
}

impl FakeRelay {
    fn decrypt(&self, wire: &str) -> String {
        String::from_utf8(self.model_keypair.decrypt(wire).unwrap()).unwrap()
    }

    fn encrypt_to_client(&self, request: &RelayChatRequest, text: &str) -> String {
        let client_public_key = hex32(request.client_public_key_hex.as_deref().unwrap());
        encrypt_to_model(&client_public_key, text.as_bytes()).unwrap()
    }

    fn assert_base_request(&self, request: &RelayChatRequest) {
        assert_eq!(request.e2ee_protocol.as_deref(), Some("near-v2"));
        assert_eq!(request.encryption_version, 2);
        assert_eq!(
            request.model_public_key_hex.as_deref(),
            Some(self.model_keypair.public_hex.as_str())
        );
        assert!(request.client_public_key_hex.is_some());
        if request.model_id == "glm-5-2" {
            assert!(matches!(
                request.reasoning_effort.as_deref(),
                Some("high" | "xhigh")
            ));
        } else {
            assert!(request.reasoning_effort.is_none());
        }
    }

    fn assert_tool_request(&self, request: &RelayChatRequest, call_index: usize) {
        self.assert_base_request(request);
        assert!(request.encrypt_all_fields);
        assert_eq!(request.parallel_tool_calls, Some(true));
        assert!(matches!(
            request.encrypted_tool_choice,
            Some(RelayEncryptedToolChoice::Mode(ref mode)) if mode == "auto"
        ));

        let tools = request.encrypted_tools.as_ref().unwrap();
        assert_eq!(tools.len(), 1);
        let function = &tools[0].function;
        assert_eq!(self.decrypt(&function.encrypted_name), TOOL_NAME);
        assert_eq!(
            self.decrypt(function.encrypted_description.as_deref().unwrap()),
            TOOL_DESCRIPTION
        );
        let parameters: serde_json::Value =
            serde_json::from_str(&self.decrypt(&function.encrypted_parameters)).unwrap();
        assert_eq!(
            parameters["properties"]["sentinelProperty"]["type"],
            "string"
        );

        let serialized = serde_json::to_string(request).unwrap();
        for secret in [
            TOOL_NAME,
            TOOL_DESCRIPTION,
            "sentinelProperty",
            USER_PROMPT,
            TOOL_ARGUMENTS,
            TOOL_ARGUMENTS_2,
            TOOL_RESULT.trim(),
            TOOL_RESULT_2.trim(),
            MESSAGE_NAME,
            REFUSAL_HISTORY,
        ] {
            assert!(
                !serialized.contains(secret),
                "relay request leaked plaintext sentinel"
            );
        }

        let user = request
            .encrypted_messages
            .iter()
            .find(|message| message.role == "user")
            .unwrap();
        assert_eq!(
            self.decrypt(user.encrypted_content.as_deref().unwrap()),
            USER_PROMPT
        );
        assert_eq!(
            self.decrypt(user.encrypted_name.as_deref().unwrap()),
            MESSAGE_NAME
        );

        if call_index == 1 {
            let assistant = request
                .encrypted_messages
                .iter()
                .find(|message| message.role == "assistant")
                .unwrap();
            let tool_calls = assistant.encrypted_tool_calls.as_ref().unwrap();
            assert_eq!(
                self.decrypt(assistant.encrypted_refusal.as_deref().unwrap()),
                REFUSAL_HISTORY
            );
            assert_eq!(tool_calls.len(), 2);
            let tool_call = &tool_calls[0];
            assert_eq!(self.decrypt(&tool_call.function.encrypted_name), TOOL_NAME);
            assert_eq!(
                self.decrypt(&tool_call.function.encrypted_arguments),
                TOOL_ARGUMENTS
            );
            let second_call = &tool_calls[1];
            assert_eq!(second_call.id, "call_secret_2");
            assert_eq!(
                self.decrypt(&second_call.function.encrypted_name),
                TOOL_NAME
            );
            assert_eq!(
                self.decrypt(&second_call.function.encrypted_arguments),
                TOOL_ARGUMENTS_2
            );
            let tools = request
                .encrypted_messages
                .iter()
                .filter(|message| message.role == "tool")
                .collect::<Vec<_>>();
            assert_eq!(tools.len(), 2);
            assert_eq!(tools[0].tool_call_id.as_deref(), Some("call_secret_1"));
            assert_eq!(
                self.decrypt(tools[0].encrypted_content.as_deref().unwrap()),
                TOOL_RESULT
            );
            assert_eq!(tools[1].tool_call_id.as_deref(), Some("call_secret_2"));
            assert_eq!(
                self.decrypt(tools[1].encrypted_content.as_deref().unwrap()),
                TOOL_RESULT_2
            );
        }
    }
}

#[async_trait]
impl RelayApi for FakeRelay {
    async fn list_models(&self, _api_key: &str) -> Result<Vec<RelayModel>> {
        Ok(vec![test_model(), reasoning_model()])
    }

    async fn complete(
        &self,
        _api_key: &str,
        request: &RelayChatRequest,
    ) -> Result<RelayCompletion> {
        if self.mode == FakeMode::Fail402 {
            return Err(CoreError::Relay("402: insufficient credit".into()));
        }
        if self.mode == FakeMode::Text {
            self.assert_base_request(request);
            assert!(!request.encrypt_all_fields);
            return Ok(RelayCompletion {
                id: "relay-text".into(),
                model: Some("google/gemma-4-31B-it".into()),
                encrypted_content: Some(self.encrypt_to_client(request, "hello from fake relay")),
                encrypted_reasoning_content: None,
                encrypted_refusal: None,
                encrypted_tool_calls: vec![],
                finish_reason: Some("stop".into()),
                usage: RelayUsage {
                    prompt_tokens: Some(10),
                    completion_tokens: Some(4),
                    total_tokens: Some(14),
                },
            });
        }

        let call_index = self.calls.fetch_add(1, Ordering::SeqCst);
        self.assert_tool_request(request, call_index);
        if call_index == 0 {
            let encrypted_name = if self.mode == FakeMode::TamperedTool {
                "not-provider-ciphertext".to_string()
            } else {
                self.encrypt_to_client(request, TOOL_NAME)
            };
            return Ok(RelayCompletion {
                id: "relay-tool-1".into(),
                model: Some("google/gemma-4-31B-it".into()),
                encrypted_content: None,
                encrypted_reasoning_content: None,
                encrypted_refusal: None,
                encrypted_tool_calls: vec![
                    RelayEncryptedToolCall {
                        id: "call_secret_1".into(),
                        kind: "function".into(),
                        function: RelayEncryptedFunctionCall {
                            encrypted_name,
                            encrypted_arguments: self.encrypt_to_client(request, TOOL_ARGUMENTS),
                        },
                    },
                    RelayEncryptedToolCall {
                        id: "call_secret_2".into(),
                        kind: "function".into(),
                        function: RelayEncryptedFunctionCall {
                            encrypted_name: self.encrypt_to_client(request, TOOL_NAME),
                            encrypted_arguments: self.encrypt_to_client(request, TOOL_ARGUMENTS_2),
                        },
                    },
                ],
                finish_reason: Some("tool_calls".into()),
                usage: RelayUsage {
                    prompt_tokens: Some(20),
                    completion_tokens: Some(8),
                    total_tokens: Some(28),
                },
            });
        }
        Ok(RelayCompletion {
            id: "relay-tool-2".into(),
            model: Some("google/gemma-4-31B-it".into()),
            encrypted_content: Some(self.encrypt_to_client(request, "tool loop complete")),
            encrypted_reasoning_content: None,
            encrypted_refusal: None,
            encrypted_tool_calls: vec![],
            finish_reason: Some("stop".into()),
            usage: RelayUsage {
                prompt_tokens: Some(30),
                completion_tokens: Some(4),
                total_tokens: Some(34),
            },
        })
    }

    async fn stream(&self, _api_key: &str, request: &RelayChatRequest) -> Result<RelayStream> {
        if self.mode == FakeMode::Text {
            self.assert_base_request(request);
            let delta_1 = self.encrypt_to_client(request, "Hello ");
            let delta_2 = self.encrypt_to_client(request, "world");
            return Ok(Box::pin(stream::iter(vec![
                Ok(RelayEvent::Delta {
                    content: Some(delta_1),
                    reasoning: None,
                    refusal: None,
                    tool_calls: vec![],
                    sequence: 1,
                }),
                Ok(RelayEvent::Delta {
                    content: Some(delta_2),
                    reasoning: None,
                    refusal: None,
                    tool_calls: vec![],
                    sequence: 2,
                }),
                Ok(RelayEvent::Completed {
                    usage: RelayUsage {
                        prompt_tokens: Some(10),
                        completion_tokens: Some(2),
                        total_tokens: Some(12),
                    },
                    finish_reason: Some("stop".into()),
                }),
            ])));
        }

        if self.mode == FakeMode::StreamCancelled {
            self.assert_base_request(request);
            return Ok(Box::pin(stream::iter(vec![Ok(RelayEvent::Cancelled {
                reason: Some("relay stopped the request".into()),
            })])));
        }
        if self.mode == FakeMode::StreamFailed {
            self.assert_base_request(request);
            return Ok(Box::pin(stream::iter(vec![Ok(RelayEvent::Failed {
                error: "provider failed".into(),
            })])));
        }
        if self.mode == FakeMode::StreamEnds {
            self.assert_base_request(request);
            return Ok(Box::pin(stream::empty()));
        }
        if self.mode == FakeMode::StreamPending {
            self.assert_base_request(request);
            return Ok(Box::pin(stream::pending()));
        }

        let call_index = self.calls.fetch_add(1, Ordering::SeqCst);
        self.assert_tool_request(request, call_index);
        if call_index == 0 {
            let events = vec![
                Ok(RelayEvent::Delta {
                    content: None,
                    reasoning: None,
                    refusal: None,
                    tool_calls: vec![RelayEncryptedToolCallDelta {
                        index: 0,
                        id: Some("call_secret_1".into()),
                        kind: Some("function".into()),
                        function: Some(RelayEncryptedFunctionCallDelta {
                            encrypted_name: Some(self.encrypt_to_client(request, TOOL_NAME)),
                            encrypted_arguments: Some(
                                self.encrypt_to_client(request, "{\"filePath\":\""),
                            ),
                        }),
                    }],
                    sequence: 1,
                }),
                Ok(RelayEvent::Delta {
                    content: None,
                    reasoning: None,
                    refusal: None,
                    tool_calls: vec![RelayEncryptedToolCallDelta {
                        index: 1,
                        id: Some("call_secret_2".into()),
                        kind: Some("function".into()),
                        function: Some(RelayEncryptedFunctionCallDelta {
                            encrypted_name: Some(self.encrypt_to_client(request, TOOL_NAME)),
                            encrypted_arguments: Some(
                                self.encrypt_to_client(request, "{\"filePath\":\""),
                            ),
                        }),
                    }],
                    sequence: 2,
                }),
                Ok(RelayEvent::Delta {
                    content: None,
                    reasoning: None,
                    refusal: None,
                    tool_calls: vec![RelayEncryptedToolCallDelta {
                        index: 0,
                        id: None,
                        kind: None,
                        function: Some(RelayEncryptedFunctionCallDelta {
                            encrypted_name: None,
                            encrypted_arguments: Some(
                                self.encrypt_to_client(request, "target.txt\"}"),
                            ),
                        }),
                    }],
                    sequence: 3,
                }),
                Ok(RelayEvent::Delta {
                    content: None,
                    reasoning: None,
                    refusal: None,
                    tool_calls: vec![RelayEncryptedToolCallDelta {
                        index: 1,
                        id: None,
                        kind: None,
                        function: Some(RelayEncryptedFunctionCallDelta {
                            encrypted_name: None,
                            encrypted_arguments: Some(
                                self.encrypt_to_client(request, "other.txt\"}"),
                            ),
                        }),
                    }],
                    sequence: 4,
                }),
                Ok(RelayEvent::Completed {
                    usage: RelayUsage {
                        prompt_tokens: Some(20),
                        completion_tokens: Some(8),
                        total_tokens: Some(28),
                    },
                    finish_reason: Some("tool_calls".into()),
                }),
            ];
            let events = stream::iter(events);
            if self.mode == FakeMode::ToolsOpenAfterCompleted {
                return Ok(Box::pin(events.chain(stream::pending())));
            }
            return Ok(Box::pin(events));
        }

        Ok(Box::pin(stream::iter(vec![
            Ok(RelayEvent::Delta {
                content: Some(self.encrypt_to_client(request, "tool loop complete")),
                reasoning: None,
                refusal: None,
                tool_calls: vec![],
                sequence: 1,
            }),
            Ok(RelayEvent::Completed {
                usage: RelayUsage {
                    prompt_tokens: Some(30),
                    completion_tokens: Some(4),
                    total_tokens: Some(34),
                },
                finish_reason: Some("stop".into()),
            }),
        ])))
    }
}

fn test_model() -> RelayModel {
    RelayModel {
        id: "gemma-4-31b".into(),
        label: "Gemma".into(),
        short_label: "Gemma".into(),
        model: "google/gemma-4-31B-it".into(),
        base_url: "https://gemma-4-31b.completions.near.ai/v1".into(),
        provider: "near".into(),
        supported_reasoning_efforts: Vec::new(),
    }
}

fn reasoning_model() -> RelayModel {
    RelayModel {
        id: "glm-5-2".into(),
        label: "GLM-5.2".into(),
        short_label: "GLM 5.2".into(),
        model: "z-ai/glm-5.2".into(),
        base_url: "https://glm-5-2.completions.near.ai/v1".into(),
        provider: "near".into(),
        supported_reasoning_efforts: vec![
            "low".into(),
            "medium".into(),
            "high".into(),
            "xhigh".into(),
        ],
    }
}

async fn spawn_proxy(mode: FakeMode) -> (String, CancellationToken, Arc<ProxyCore>) {
    spawn_proxy_with_history(mode, None).await
}

async fn spawn_proxy_with_history(
    mode: FakeMode,
    history_path: Option<PathBuf>,
) -> (String, CancellationToken, Arc<ProxyCore>) {
    let model_keypair = ClientKeypair::generate();
    let model_public_key = model_keypair.public_hex.clone();
    let reasoning_model_public_key = model_public_key.clone();
    let relay = Arc::new(FakeRelay {
        mode,
        model_keypair,
        calls: AtomicUsize::new(0),
    });
    let core = Arc::new(ProxyCore::new_with_history(
        relay,
        Some("axm_test".into()),
        Duration::from_secs(900),
        None,
        history_path,
    ));
    core.seed_for_test(test_model(), model_public_key);
    core.seed_for_test(reasoning_model(), reasoning_model_public_key);

    let listener = bind(0).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let cancel = CancellationToken::new();
    let cancellation = cancel.clone();
    let server_core = core.clone();
    tokio::spawn(async move {
        let _ = serve(listener, server_core, cancellation).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (format!("http://127.0.0.1:{port}"), cancel, core)
}

async fn wait_for_history(core: &ProxyCore, expected: usize) -> Vec<RequestLogEntry> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let entries = core.recent_requests(100);
            if entries.len() >= expected {
                break entries;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("request audit record was not written")
}

fn assert_verified_receipt(entry: &RequestLogEntry, status: RequestTerminalStatus, stream: bool) {
    assert_eq!(entry.model, "gemma-4-31b");
    assert_eq!(entry.provider, "near");
    assert_eq!(entry.stream, stream);
    assert_eq!(entry.status, status);
    assert!(entry.completed_at_unix_ms >= entry.started_at_unix_ms);
    assert_eq!(entry.e2ee.protocol.as_deref(), Some("near-v2"));
    assert_eq!(entry.e2ee.encryption_version, Some(2));
    assert!(entry.e2ee.request_encrypted);
    assert!(entry.e2ee.ephemeral_client_key);
    assert!(entry.tee.verified);
    assert!(entry.tee.verified_at_unix_ms.is_some());
    assert!(entry.tee.age_ms.is_some());
    assert_eq!(entry.tee.model_key_sha256.as_deref().unwrap().len(), 64);
    assert_eq!(entry.tee.tls_spki_sha256.as_deref().unwrap().len(), 64);
    assert!(!entry.tee.checks.is_empty());
    assert!(entry.tee.checks.iter().all(|check| check.ok));
}

fn tool_definition() -> serde_json::Value {
    json!({
        "type": "function",
        "function": {
            "name": TOOL_NAME,
            "description": TOOL_DESCRIPTION,
            "parameters": {
                "type": "object",
                "properties": {
                    "sentinelProperty": {"type": "string"}
                },
                "required": ["sentinelProperty"]
            }
        }
    })
}

fn initial_tool_request(stream: bool) -> serde_json::Value {
    json!({
        "model": "gemma-4-31b",
        "messages": [{"role": "user", "name": MESSAGE_NAME, "content": USER_PROMPT}],
        "tools": [tool_definition()],
        "tool_choice": "auto",
        "parallel_tool_calls": true,
        "stream": stream,
        "stream_options": {"include_usage": true}
    })
}

fn followup_tool_request(stream: bool) -> serde_json::Value {
    json!({
        "model": "gemma-4-31b",
        "messages": [
            {"role": "user", "name": MESSAGE_NAME, "content": USER_PROMPT},
            {
                "role": "assistant",
                "content": null,
                "refusal": REFUSAL_HISTORY,
                "tool_calls": [
                    {
                        "id": "call_secret_1",
                        "type": "function",
                        "function": {"name": TOOL_NAME, "arguments": TOOL_ARGUMENTS}
                    },
                    {
                        "id": "call_secret_2",
                        "type": "function",
                        "function": {"name": TOOL_NAME, "arguments": TOOL_ARGUMENTS_2}
                    }
                ]
            },
            {
                "role": "tool",
                "tool_call_id": "call_secret_1",
                "content": TOOL_RESULT
            },
            {
                "role": "tool",
                "tool_call_id": "call_secret_2",
                "content": TOOL_RESULT_2
            }
        ],
        "tools": [tool_definition()],
        "tool_choice": "auto",
        "parallel_tool_calls": true,
        "stream": stream,
        "stream_options": {"include_usage": true}
    })
}

#[tokio::test]
async fn non_stream_decrypts_and_returns_openai_shape() {
    let (base, cancel, core) = spawn_proxy(FakeMode::Text).await;
    let response = reqwest::Client::new()
        .post(format!("{base}/v1/chat/completions"))
        .json(&json!({
            "model": "gemma-4-31b",
            "messages": [{"role": "user", "content": "hi"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["object"], "chat.completion");
    assert_eq!(
        body["choices"][0]["message"]["content"],
        "hello from fake relay"
    );
    assert_eq!(body["choices"][0]["finish_reason"], "stop");
    assert_eq!(body["usage"]["total_tokens"], 14);
    let history = wait_for_history(&core, 1).await;
    assert_eq!(history.len(), 1);
    let entry = &history[0];
    assert_verified_receipt(entry, RequestTerminalStatus::Completed, false);
    assert!(entry.verified_completed());
    assert!(entry.e2ee.backend_key_accepted);
    assert!(entry.e2ee.response_decrypted);
    assert_eq!(entry.prompt_tokens, 10);
    assert_eq!(entry.completion_tokens, 4);
    assert_eq!(entry.finish_reason.as_deref(), Some("stop"));
    assert_eq!(entry.error_kind, None);
    assert_eq!(core.counters.active_requests.load(Ordering::Relaxed), 0);
    cancel.cancel();
}

#[tokio::test]
async fn reasoning_effort_is_validated_and_relayed_for_stream_and_non_stream() {
    let (base, cancel, core) = spawn_proxy(FakeMode::Text).await;
    let client = reqwest::Client::new();

    let non_stream = client
        .post(format!("{base}/v1/chat/completions"))
        .json(&json!({
            "model": "glm-5-2",
            "messages": [{"role": "user", "content": "hi"}],
            "reasoning_effort": "high"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(non_stream.status(), 200);

    let streamed = client
        .post(format!("{base}/v1/chat/completions"))
        .json(&json!({
            "model": "glm-5-2",
            "messages": [{"role": "user", "content": "hi"}],
            "reasoning_effort": "xhigh",
            "stream": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(streamed.status(), 200);
    assert!(streamed.text().await.unwrap().contains("[DONE]"));

    let unsupported = client
        .post(format!("{base}/v1/chat/completions"))
        .json(&json!({
            "model": "gemma-4-31b",
            "messages": [{"role": "user", "content": "hi"}],
            "reasoning_effort": "high"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(unsupported.status(), 400);
    let unsupported_body: serde_json::Value = unsupported.json().await.unwrap();
    assert_eq!(unsupported_body["error"]["type"], "invalid_request_error");
    assert!(unsupported_body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("not supported for model gemma-4-31b"));

    let invalid = client
        .post(format!("{base}/v1/chat/completions"))
        .json(&json!({
            "model": "glm-5-2",
            "messages": [{"role": "user", "content": "hi"}],
            "reasoning_effort": "unbounded"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(invalid.status(), 422);

    let history = wait_for_history(&core, 3).await;
    assert_eq!(history.len(), 3);
    assert_eq!(core.counters.active_requests.load(Ordering::Relaxed), 0);
    cancel.cancel();
}

#[tokio::test]
async fn models_expose_supported_reasoning_efforts() {
    let (base, cancel, _) = spawn_proxy(FakeMode::Text).await;
    let response = reqwest::get(format!("{base}/v1/models")).await.unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    let models = body["data"].as_array().unwrap();
    let glm = models
        .iter()
        .find(|model| model["id"] == "glm-5-2")
        .unwrap();
    let gemma = models
        .iter()
        .find(|model| model["id"] == "gemma-4-31b")
        .unwrap();
    assert_eq!(
        glm["supported_reasoning_efforts"],
        json!(["low", "medium", "high", "xhigh"])
    );
    assert_eq!(gemma["supported_reasoning_efforts"], json!([]));
    cancel.cancel();
}

#[tokio::test]
async fn non_stream_tool_loop_encrypts_history_and_reconstructs_response() {
    let (base, cancel, _) = spawn_proxy(FakeMode::Tools).await;
    let client = reqwest::Client::new();

    let first = client
        .post(format!("{base}/v1/chat/completions"))
        .json(&initial_tool_request(false))
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);
    let first_body: serde_json::Value = first.json().await.unwrap();
    assert!(first_body["choices"][0]["message"]["content"].is_null());
    assert_eq!(first_body["choices"][0]["finish_reason"], "tool_calls");
    assert_eq!(
        first_body["choices"][0]["message"]["tool_calls"][0]["function"]["name"],
        TOOL_NAME
    );
    assert_eq!(
        first_body["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"],
        TOOL_ARGUMENTS
    );
    assert_eq!(
        first_body["choices"][0]["message"]["tool_calls"][1]["id"],
        "call_secret_2"
    );
    assert_eq!(
        first_body["choices"][0]["message"]["tool_calls"][1]["function"]["arguments"],
        TOOL_ARGUMENTS_2
    );

    let second = client
        .post(format!("{base}/v1/chat/completions"))
        .json(&followup_tool_request(false))
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), 200);
    let second_body: serde_json::Value = second.json().await.unwrap();
    assert_eq!(
        second_body["choices"][0]["message"]["content"],
        "tool loop complete"
    );
    assert_eq!(second_body["choices"][0]["finish_reason"], "stop");
    cancel.cancel();
}

#[tokio::test]
async fn stream_tool_loop_preserves_independent_fragments_and_finish_reasons() {
    let (base, cancel, _) = spawn_proxy(FakeMode::Tools).await;
    let client = reqwest::Client::new();

    let first = client
        .post(format!("{base}/v1/chat/completions"))
        .json(&initial_tool_request(true))
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);
    let first_text = first.text().await.unwrap();
    assert!(first_text.contains("\"finish_reason\":\"tool_calls\""));
    assert!(first_text.contains(TOOL_NAME));
    assert!(first_text.contains("{\\\"filePath\\\":\\\""));
    assert!(first_text.contains("target.txt\\\"}"));
    assert!(first_text.contains("other.txt\\\"}"));
    assert!(first_text.contains("\"index\":0"));
    assert!(first_text.contains("\"index\":1"));
    assert!(first_text.contains("[DONE]"));

    let second = client
        .post(format!("{base}/v1/chat/completions"))
        .json(&followup_tool_request(true))
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), 200);
    let second_text = second.text().await.unwrap();
    assert!(second_text.contains("tool loop complete"));
    assert!(second_text.contains("\"finish_reason\":\"stop\""));
    assert!(second_text.contains("\"total_tokens\":34"));
    cancel.cancel();
}

#[tokio::test]
async fn stream_ends_on_completed_even_if_relay_connection_stays_open() {
    let (base, cancel, _) = spawn_proxy(FakeMode::ToolsOpenAfterCompleted).await;
    let response = reqwest::Client::new()
        .post(format!("{base}/v1/chat/completions"))
        .json(&initial_tool_request(true))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let text = tokio::time::timeout(Duration::from_secs(1), response.text())
        .await
        .expect("proxy stream did not close after the completed event")
        .unwrap();
    assert!(text.contains("\"finish_reason\":\"tool_calls\""));
    assert!(text.contains("[DONE]"));
    cancel.cancel();
}

#[tokio::test]
async fn stream_translates_text_to_openai_chunks() {
    let (base, cancel, core) = spawn_proxy(FakeMode::Text).await;
    let response = reqwest::Client::new()
        .post(format!("{base}/v1/chat/completions"))
        .json(&json!({
            "model": "gemma-4-31b",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": true,
            "stream_options": {"include_usage": true}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let text = response.text().await.unwrap();
    assert!(text.contains("\"role\":\"assistant\""));
    assert!(text.contains("Hello "));
    assert!(text.contains("world"));
    assert!(text.contains("\"finish_reason\":\"stop\""));
    assert!(text.contains("\"total_tokens\":12"));
    assert!(text.contains("[DONE]"));
    let history = wait_for_history(&core, 1).await;
    assert_eq!(history.len(), 1);
    let entry = &history[0];
    assert_verified_receipt(entry, RequestTerminalStatus::Completed, true);
    assert!(entry.verified_completed());
    assert!(entry.e2ee.backend_key_accepted);
    assert!(entry.e2ee.response_decrypted);
    assert_eq!(entry.prompt_tokens, 10);
    assert_eq!(entry.completion_tokens, 2);
    assert_eq!(entry.finish_reason.as_deref(), Some("stop"));
    assert_eq!(core.counters.active_requests.load(Ordering::Relaxed), 0);
    cancel.cancel();
}

#[tokio::test]
async fn rejects_invalid_tool_roles_legacy_forms_and_tool_count() {
    let (base, cancel, core) = spawn_proxy(FakeMode::Text).await;
    let client = reqwest::Client::new();

    let missing_id = client
        .post(format!("{base}/v1/chat/completions"))
        .json(&json!({
            "model": "gemma-4-31b",
            "messages": [{"role": "tool", "content": "secret"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(missing_id.status(), 400);

    let legacy = client
        .post(format!("{base}/v1/chat/completions"))
        .json(&json!({
            "model": "gemma-4-31b",
            "messages": [{"role": "user", "content": "hi"}],
            "functions": []
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(legacy.status(), 400);

    let tools = (0..129)
        .map(|index| {
            json!({
                "type": "function",
                "function": {
                    "name": format!("tool_{index}"),
                    "parameters": {"type": "object"}
                }
            })
        })
        .collect::<Vec<_>>();
    let too_many = client
        .post(format!("{base}/v1/chat/completions"))
        .json(&json!({
            "model": "gemma-4-31b",
            "messages": [{"role": "user", "content": "hi"}],
            "tools": tools
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(too_many.status(), 400);
    let history = wait_for_history(&core, 3).await;
    assert_eq!(history.len(), 3);
    assert!(history
        .iter()
        .all(|entry| entry.status == RequestTerminalStatus::Failed));
    assert!(history
        .iter()
        .all(|entry| entry.error_kind.as_deref() == Some("invalid_request_error")));
    assert!(history.iter().all(|entry| !entry.verified_completed()));
    assert_eq!(core.counters.active_requests.load(Ordering::Relaxed), 0);
    cancel.cancel();
}

#[tokio::test]
async fn rejects_aggregate_encrypted_request_over_two_mib() {
    let (base, cancel, _) = spawn_proxy(FakeMode::Text).await;
    let large_value = "x".repeat(120_000);
    let tools = (0..10)
        .map(|index| {
            json!({
                "type": "function",
                "function": {
                    "name": format!("large_{index}"),
                    "parameters": {
                        "type": "object",
                        "description": large_value
                    }
                }
            })
        })
        .collect::<Vec<_>>();
    let response = reqwest::Client::new()
        .post(format!("{base}/v1/chat/completions"))
        .json(&json!({
            "model": "gemma-4-31b",
            "messages": [{"role": "user", "content": "hi"}],
            "tools": tools
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 413);
    cancel.cancel();
}

#[tokio::test]
async fn tampered_tool_ciphertext_fails_closed() {
    let (base, cancel, core) = spawn_proxy(FakeMode::TamperedTool).await;
    let response = reqwest::Client::new()
        .post(format!("{base}/v1/chat/completions"))
        .json(&initial_tool_request(false))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 502);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["type"], "decryption_error");
    assert!(!body.to_string().contains("not-provider-ciphertext"));
    let history = wait_for_history(&core, 1).await;
    let entry = &history[0];
    assert_verified_receipt(entry, RequestTerminalStatus::Failed, false);
    assert!(entry.e2ee.backend_key_accepted);
    assert!(!entry.e2ee.response_decrypted);
    assert_eq!(entry.error_kind.as_deref(), Some("decryption_error"));
    assert!(!entry.verified_completed());
    assert_eq!(core.counters.active_requests.load(Ordering::Relaxed), 0);
    cancel.cancel();
}

#[tokio::test]
async fn missing_api_key_is_401() {
    let model_keypair = ClientKeypair::generate();
    let model_public_key = model_keypair.public_hex.clone();
    let relay = Arc::new(FakeRelay {
        mode: FakeMode::Text,
        model_keypair,
        calls: AtomicUsize::new(0),
    });
    let core = Arc::new(ProxyCore::new(relay, None, Duration::from_secs(900), None));
    core.seed_for_test(test_model(), model_public_key);
    let listener = bind(0).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let cancel = CancellationToken::new();
    let cancellation = cancel.clone();
    let server_core = core.clone();
    tokio::spawn(async move {
        let _ = serve(listener, server_core, cancellation).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/v1/chat/completions"))
        .json(&json!({"model": "gemma-4-31b", "messages": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    let history = wait_for_history(&core, 1).await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].status, RequestTerminalStatus::Failed);
    assert_eq!(
        history[0].error_kind.as_deref(),
        Some("authentication_error")
    );
    assert!(!history[0].e2ee.request_encrypted);
    assert!(!history[0].tee.verified);
    assert!(!history[0].verified_completed());
    assert_eq!(core.counters.active_requests.load(Ordering::Relaxed), 0);
    cancel.cancel();
}

#[tokio::test]
async fn insufficient_credit_maps_to_402() {
    let (base, cancel, core) = spawn_proxy(FakeMode::Fail402).await;
    let response = reqwest::Client::new()
        .post(format!("{base}/v1/chat/completions"))
        .json(&json!({
            "model": "gemma-4-31b",
            "messages": [{"role": "user", "content": "hi"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 402);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["type"], "insufficient_credit");
    let history = wait_for_history(&core, 1).await;
    let entry = &history[0];
    assert_verified_receipt(entry, RequestTerminalStatus::Failed, false);
    assert!(!entry.e2ee.backend_key_accepted);
    assert!(!entry.e2ee.response_decrypted);
    assert_eq!(entry.error_kind.as_deref(), Some("insufficient_credit"));
    assert!(!entry.verified_completed());
    assert_eq!(core.counters.active_requests.load(Ordering::Relaxed), 0);
    cancel.cancel();
}

#[tokio::test]
async fn request_history_survives_proxy_core_rebuild() {
    let directory = tempfile::tempdir().unwrap();
    let history_path = directory.path().join("request-history.json");
    let (base, cancel, core) =
        spawn_proxy_with_history(FakeMode::Text, Some(history_path.clone())).await;
    let response = reqwest::Client::new()
        .post(format!("{base}/v1/chat/completions"))
        .json(&json!({
            "model": "gemma-4-31b",
            "messages": [{"role": "user", "content": "hi"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let _ = response.json::<serde_json::Value>().await.unwrap();
    let original = wait_for_history(&core, 1).await;
    cancel.cancel();

    let rebuilt = ProxyCore::new_with_history(
        core.relay.clone(),
        core.api_key(),
        Duration::from_secs(900),
        None,
        Some(history_path),
    );
    assert_eq!(rebuilt.recent_requests(100), original);
}

#[tokio::test]
async fn relay_cancelled_stream_is_recorded_once_as_cancelled() {
    let (base, cancel, core) = spawn_proxy(FakeMode::StreamCancelled).await;
    let response = reqwest::Client::new()
        .post(format!("{base}/v1/chat/completions"))
        .json(&json!({
            "model": "gemma-4-31b",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(response
        .text()
        .await
        .unwrap()
        .contains("\"type\":\"cancelled\""));
    let history = wait_for_history(&core, 1).await;
    assert_eq!(history.len(), 1);
    let entry = &history[0];
    assert_verified_receipt(entry, RequestTerminalStatus::Cancelled, true);
    assert!(entry.e2ee.backend_key_accepted);
    assert!(!entry.e2ee.response_decrypted);
    assert_eq!(entry.error_kind.as_deref(), Some("relay_cancelled"));
    assert!(!entry.verified_completed());
    assert_eq!(core.counters.active_requests.load(Ordering::Relaxed), 0);
    cancel.cancel();
}

#[tokio::test]
async fn failed_and_incomplete_streams_are_never_recorded_as_completed() {
    for (mode, expected_error) in [
        (FakeMode::StreamFailed, "upstream_error"),
        (FakeMode::StreamEnds, "stream_ended_without_completion"),
    ] {
        let (base, cancel, core) = spawn_proxy(mode).await;
        let response = reqwest::Client::new()
            .post(format!("{base}/v1/chat/completions"))
            .json(&json!({
                "model": "gemma-4-31b",
                "messages": [{"role": "user", "content": "hi"}],
                "stream": true
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let _ = response.text().await.unwrap();
        let history = wait_for_history(&core, 1).await;
        assert_eq!(history.len(), 1);
        let entry = &history[0];
        assert_verified_receipt(entry, RequestTerminalStatus::Failed, true);
        assert!(entry.e2ee.backend_key_accepted);
        assert_eq!(entry.error_kind.as_deref(), Some(expected_error));
        assert!(!entry.verified_completed());
        assert_eq!(core.counters.active_requests.load(Ordering::Relaxed), 0);
        cancel.cancel();
    }
}

#[tokio::test]
async fn dropping_stream_body_records_one_client_cancellation() {
    let (base, cancel, core) = spawn_proxy(FakeMode::StreamPending).await;
    let response = reqwest::Client::new()
        .post(format!("{base}/v1/chat/completions"))
        .json(&json!({
            "model": "gemma-4-31b",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    drop(response);

    let history = wait_for_history(&core, 1).await;
    assert_eq!(history.len(), 1);
    let entry = &history[0];
    assert_verified_receipt(entry, RequestTerminalStatus::Cancelled, true);
    assert!(entry.e2ee.backend_key_accepted);
    assert_eq!(entry.error_kind.as_deref(), Some("client_disconnected"));
    assert!(!entry.verified_completed());
    assert_eq!(core.counters.active_requests.load(Ordering::Relaxed), 0);
    cancel.cancel();
}

#[tokio::test]
async fn client_key_roundtrip_sanity() {
    let keypair = ClientKeypair::generate();
    let public_key = hex32(&keypair.public_hex);
    let wire = encrypt_to_model(&public_key, b"abc").unwrap();
    assert_eq!(keypair.decrypt(&wire).unwrap(), b"abc");
}
