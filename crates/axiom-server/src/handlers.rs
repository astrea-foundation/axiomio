//! OpenAI-compatible HTTP handlers: `/v1/chat/completions`, `/v1/models`, `/healthz`.

use std::sync::Arc;

use axiom_core::attestation::now_unix;
use axiom_core::events::{E2eeAuditReceipt, TeeAuditReceipt};
use axiom_core::openai::{
    validate_finish_reason, validate_tool_calls, ApiError, AssistantMessage, ChatCompletion,
    ChatRequest, Choice, FunctionCall, ModelEntry, ModelList, ToolCall, ToolChoice, Usage,
    MAX_RELAY_REQUEST_BYTES,
};
use axiom_core::provider::CipherSession;
use axiom_core::relay::{
    RelayChatRequest, RelayEncryptedFunctionCall, RelayEncryptedFunctionDefinition,
    RelayEncryptedNamedFunction, RelayEncryptedNamedToolChoice, RelayEncryptedTool,
    RelayEncryptedToolCall, RelayEncryptedToolChoice, RelayMessage,
};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::audit::{RequestAudit, RequestSecurityReceipt};
use crate::sse::openai_stream;
use crate::state::ProxyCore;

/// Handler error carrying the OpenAI error type + HTTP status.
pub struct AppError {
    status: StatusCode,
    kind: String,
    message: String,
}

impl AppError {
    fn new(status: StatusCode, kind: &str, message: impl Into<String>) -> Self {
        Self {
            status,
            kind: kind.into(),
            message: message.into(),
        }
    }

    fn kind(&self) -> &str {
        &self.kind
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.status, Json(ApiError::new(&self.kind, self.message))).into_response()
    }
}

fn require_key(core: &ProxyCore) -> std::result::Result<String, AppError> {
    core.api_key().ok_or_else(|| {
        AppError::new(
            StatusCode::UNAUTHORIZED,
            "authentication_error",
            "no API key configured in the proxy",
        )
    })
}

/// Map a relay error to the closest OpenAI-style HTTP error. The backend's 402 (insufficient
/// credit) is surfaced verbatim so tools can distinguish "top up" from a real failure.
fn relay_error(e: axiom_core::CoreError) -> AppError {
    let msg = e.to_string();
    if msg.contains("402") {
        AppError::new(
            StatusCode::PAYMENT_REQUIRED,
            "insufficient_credit",
            "out of credit — top up your Axiom balance",
        )
    } else {
        AppError::new(StatusCode::BAD_GATEWAY, "upstream_error", msg)
    }
}

async fn build_relay_request(
    core: &ProxyCore,
    req: &ChatRequest,
) -> std::result::Result<
    (
        RelayChatRequest,
        Box<dyn CipherSession>,
        RequestSecurityReceipt,
    ),
    AppError,
> {
    req.validate().map_err(|message| {
        AppError::new(StatusCode::BAD_REQUEST, "invalid_request_error", message)
    })?;
    let model = core.resolve_model(&req.model).await.map_err(|_| {
        AppError::new(
            StatusCode::NOT_FOUND,
            "model_not_found",
            format!("unknown model: {}", req.model),
        )
    })?;
    let engine = core
        .registry
        .for_model(&model)
        .map_err(|e| AppError::new(StatusCode::BAD_GATEWAY, "provider_error", e.to_string()))?;
    let reasoning_effort = req
        .reasoning_effort
        .map(|effort| effort.as_str().to_string());
    if let Some(effort) = &reasoning_effort {
        if !model
            .supported_reasoning_efforts
            .iter()
            .any(|supported| supported == effort)
        {
            return Err(AppError::new(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                format!("reasoning_effort is not supported for model {}", model.id),
            ));
        }
    }

    let attestation = core
        .ensure_verified_with_receipt(&model)
        .await
        .map_err(|e| AppError::new(StatusCode::BAD_GATEWAY, "attestation_failed", e.to_string()))?;
    let verified = &attestation.verified;
    let mut session = engine
        .cipher
        .new_session(&verified.model_public_key_hex)
        .map_err(|e| AppError::new(StatusCode::BAD_GATEWAY, "attestation_failed", e.to_string()))?;

    let mut encrypted_messages = Vec::with_capacity(req.messages.len());
    for message in &req.messages {
        let text = message
            .content_text()
            .map_err(|m| AppError::new(StatusCode::BAD_REQUEST, "invalid_request_error", m))?;
        let encrypted_content = text
            .as_deref()
            .map(|value| encrypt_text(session.as_mut(), value))
            .transpose()?;
        let encrypted_reasoning_content = message
            .reasoning_content
            .as_deref()
            .map(|value| encrypt_text(session.as_mut(), value))
            .transpose()?;
        let encrypted_name = message
            .name
            .as_deref()
            .map(|value| encrypt_text(session.as_mut(), value))
            .transpose()?;
        let encrypted_refusal = message
            .refusal
            .as_deref()
            .map(|value| encrypt_text(session.as_mut(), value))
            .transpose()?;
        let encrypted_tool_calls = message
            .tool_calls
            .as_ref()
            .map(|tool_calls| {
                tool_calls
                    .iter()
                    .map(|tool_call| {
                        Ok(RelayEncryptedToolCall {
                            id: tool_call.id.clone(),
                            kind: tool_call.kind.clone(),
                            function: RelayEncryptedFunctionCall {
                                encrypted_name: encrypt_text(
                                    session.as_mut(),
                                    &tool_call.function.name,
                                )?,
                                encrypted_arguments: encrypt_text(
                                    session.as_mut(),
                                    &tool_call.function.arguments,
                                )?,
                            },
                        })
                    })
                    .collect::<std::result::Result<Vec<_>, AppError>>()
            })
            .transpose()?;
        encrypted_messages.push(RelayMessage {
            role: message.role.as_str().to_string(),
            encrypted_content,
            encrypted_reasoning_content,
            encrypted_name,
            encrypted_refusal,
            encrypted_tool_calls,
            tool_call_id: message.tool_call_id.clone(),
        });
    }

    let encrypted_tools = req
        .tools
        .as_ref()
        .map(|tools| {
            tools
                .iter()
                .map(|tool| {
                    let parameters =
                        serde_json::to_string(&tool.function.parameters).map_err(|_| {
                            AppError::new(
                                StatusCode::BAD_REQUEST,
                                "invalid_request_error",
                                "tool function parameters could not be serialized",
                            )
                        })?;
                    Ok(RelayEncryptedTool {
                        kind: tool.kind.clone(),
                        function: RelayEncryptedFunctionDefinition {
                            encrypted_name: encrypt_text(session.as_mut(), &tool.function.name)?,
                            encrypted_description: tool
                                .function
                                .description
                                .as_deref()
                                .map(|value| encrypt_text(session.as_mut(), value))
                                .transpose()?,
                            encrypted_parameters: encrypt_text(session.as_mut(), &parameters)?,
                            strict: tool.function.strict,
                        },
                    })
                })
                .collect::<std::result::Result<Vec<_>, AppError>>()
        })
        .transpose()?;

    let encrypted_tool_choice = req
        .tool_choice
        .as_ref()
        .map(|choice| match choice {
            ToolChoice::Mode(mode) => Ok(RelayEncryptedToolChoice::Mode(mode.clone())),
            ToolChoice::Named(named) => Ok(RelayEncryptedToolChoice::Named(
                RelayEncryptedNamedToolChoice {
                    kind: named.kind.clone(),
                    function: RelayEncryptedNamedFunction {
                        encrypted_name: encrypt_text(session.as_mut(), &named.function.name)?,
                    },
                },
            )),
        })
        .transpose()?;

    let relay_req = RelayChatRequest {
        model_id: model.id.clone(),
        encryption_version: engine.cipher.encryption_version(),
        e2ee_protocol: Some(engine.cipher.protocol().to_string()),
        client_public_key_hex: session.client_public_key_hex(),
        model_public_key_hex: Some(verified.model_public_key_hex.clone()),
        encrypted_messages,
        encrypt_all_fields: req.requires_all_fields_encryption(),
        encrypted_tools,
        encrypted_tool_choice,
        parallel_tool_calls: req.parallel_tool_calls,
        stream: req.stream,
        max_tokens: req.max_tokens,
        sampling: req.sampling(),
        response_format: req.response_format.clone(),
        reasoning_effort,
    };
    let request_size = serde_json::to_vec(&relay_req)
        .map_err(|_| {
            AppError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "serialization_error",
                "failed to serialize encrypted relay request",
            )
        })?
        .len();
    if request_size > MAX_RELAY_REQUEST_BYTES {
        return Err(AppError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "invalid_request_error",
            format!("encrypted relay request exceeds {MAX_RELAY_REQUEST_BYTES} bytes"),
        ));
    }
    let key_bytes = hex::decode(&verified.model_public_key_hex)
        .unwrap_or_else(|_| verified.model_public_key_hex.as_bytes().to_vec());
    let security = RequestSecurityReceipt {
        model: model.id,
        provider: model.provider,
        e2ee: E2eeAuditReceipt {
            protocol: relay_req.e2ee_protocol.clone(),
            encryption_version: Some(relay_req.encryption_version),
            request_encrypted: true,
            backend_key_accepted: false,
            response_decrypted: false,
            ephemeral_client_key: relay_req.client_public_key_hex.is_some(),
        },
        tee: TeeAuditReceipt {
            verified: true,
            verified_at_unix_ms: Some(attestation.verified_at_unix_ms),
            age_ms: Some(attestation.age_ms),
            model_key_sha256: Some(hex::encode(Sha256::digest(&key_bytes))),
            // The attestor's TLS fingerprint is already a SHA-256 SPKI digest.
            tls_spki_sha256: verified.tls_fingerprint.clone(),
            checks: verified.checks.clone(),
        },
    };
    Ok((relay_req, session, security))
}

fn encrypt_text(
    session: &mut dyn CipherSession,
    value: &str,
) -> std::result::Result<String, AppError> {
    session.encrypt(value.as_bytes()).map_err(|_| {
        AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "encryption_error",
            "failed to encrypt provider field",
        )
    })
}

fn decrypt_text(
    session: &mut dyn CipherSession,
    value: &str,
    field: &str,
) -> std::result::Result<String, AppError> {
    let bytes = session.decrypt(value).map_err(|_| {
        AppError::new(
            StatusCode::BAD_GATEWAY,
            "decryption_error",
            format!("failed to decrypt provider {field}"),
        )
    })?;
    String::from_utf8(bytes).map_err(|_| {
        AppError::new(
            StatusCode::BAD_GATEWAY,
            "decryption_error",
            format!("provider {field} is not valid UTF-8"),
        )
    })
}

fn decrypt_optional(
    session: &mut dyn CipherSession,
    value: Option<&str>,
    field: &str,
) -> std::result::Result<Option<String>, AppError> {
    value
        .map(|wire| decrypt_text(session, wire, field))
        .transpose()
}

fn audited<T>(
    audit: &mut RequestAudit,
    result: std::result::Result<T, AppError>,
) -> std::result::Result<T, AppError> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            audit.fail(error.kind().to_string());
            Err(error)
        }
    }
}

pub async fn chat_completions(
    State(core): State<Arc<ProxyCore>>,
    Json(req): Json<ChatRequest>,
) -> std::result::Result<Response, AppError> {
    let id = format!("chatcmpl-{}", Uuid::new_v4().simple());
    let created = now_unix();
    let mut audit = RequestAudit::start(core.clone(), id.clone(), req.model.clone(), req.stream);
    let api_key = audited(&mut audit, require_key(&core))?;
    let built = build_relay_request(&core, &req).await;
    let (relay_req, mut session, security) = audited(&mut audit, built)?;
    audit.set_security(security);
    let model_label = relay_req.model_id.clone();

    if req.stream {
        let include_usage = req
            .stream_options
            .as_ref()
            .map(|o| o.include_usage)
            .unwrap_or(false);
        let stream = match core.relay.stream(&api_key, &relay_req).await {
            Ok(stream) => stream,
            Err(error) => {
                let error = relay_error(error);
                audit.fail(error.kind().to_string());
                return Err(error);
            }
        };
        audit.backend_key_accepted();
        audit.cancel_if_dropped();
        let body = openai_stream(
            audit,
            session,
            stream,
            id,
            model_label,
            created,
            include_usage,
        );
        return Ok(Sse::new(body)
            .keep_alive(KeepAlive::default())
            .into_response());
    }

    // Non-streaming.
    let completion = match core.relay.complete(&api_key, &relay_req).await {
        Ok(completion) => {
            audit.backend_key_accepted();
            completion
        }
        Err(error) => {
            let error = relay_error(error);
            audit.fail(error.kind().to_string());
            return Err(error);
        }
    };
    let content_result = decrypt_optional(
        session.as_mut(),
        completion.encrypted_content.as_deref(),
        "content",
    );
    let content = audited(&mut audit, content_result)?;
    let reasoning_result = decrypt_optional(
        session.as_mut(),
        completion.encrypted_reasoning_content.as_deref(),
        "reasoning_content",
    );
    let reasoning = audited(&mut audit, reasoning_result)?;
    let refusal_result = decrypt_optional(
        session.as_mut(),
        completion.encrypted_refusal.as_deref(),
        "refusal",
    );
    let refusal = audited(&mut audit, refusal_result)?;
    let mut tool_calls = Vec::with_capacity(completion.encrypted_tool_calls.len());
    for tool_call in &completion.encrypted_tool_calls {
        let name_result = decrypt_text(
            session.as_mut(),
            &tool_call.function.encrypted_name,
            "tool call name",
        );
        let name = audited(&mut audit, name_result)?;
        let arguments_result = decrypt_text(
            session.as_mut(),
            &tool_call.function.encrypted_arguments,
            "tool call arguments",
        );
        let arguments = audited(&mut audit, arguments_result)?;
        tool_calls.push(ToolCall {
            id: tool_call.id.clone(),
            kind: tool_call.kind.clone(),
            function: FunctionCall { name, arguments },
        });
    }
    if !tool_calls.is_empty() {
        let validation = validate_tool_calls(&tool_calls)
            .map_err(|message| AppError::new(StatusCode::BAD_GATEWAY, "upstream_error", message));
        audited(&mut audit, validation)?;
    }
    if content.is_none() && refusal.is_none() && tool_calls.is_empty() {
        let error = AppError::new(
            StatusCode::BAD_GATEWAY,
            "upstream_error",
            "provider completion contained no content, refusal, or tool calls",
        );
        audit.fail(error.kind().to_string());
        return Err(error);
    }
    let finish_reason = completion
        .finish_reason
        .as_deref()
        .unwrap_or("stop")
        .to_string();
    let finish_validation = validate_finish_reason(&finish_reason)
        .map_err(|message| AppError::new(StatusCode::BAD_GATEWAY, "upstream_error", message));
    audited(&mut audit, finish_validation)?;

    let usage = &completion.usage;
    let (pt, ct) = (
        usage.prompt_tokens.unwrap_or(0),
        usage.completion_tokens.unwrap_or(0),
    );
    audit.response_decrypted();
    audit.complete(pt, ct, finish_reason.clone());

    let out = ChatCompletion {
        id,
        object: "chat.completion",
        created,
        model: model_label,
        choices: vec![Choice {
            index: 0,
            message: AssistantMessage {
                role: "assistant",
                content,
                reasoning_content: reasoning,
                refusal,
                tool_calls: (!tool_calls.is_empty()).then_some(tool_calls),
            },
            finish_reason,
        }],
        usage: Some(Usage {
            prompt_tokens: usage.prompt_tokens.unwrap_or(0),
            completion_tokens: usage.completion_tokens.unwrap_or(0),
            total_tokens: usage.total_tokens.unwrap_or(0),
        }),
    };
    Ok(Json(out).into_response())
}

pub async fn list_models(
    State(core): State<Arc<ProxyCore>>,
) -> std::result::Result<Json<ModelList>, AppError> {
    require_key(&core)?;
    let models = core.refresh_models().await.map_err(relay_error)?;
    Ok(Json(ModelList {
        object: "list",
        data: models
            .into_iter()
            .map(|m| ModelEntry {
                id: m.id,
                object: "model",
                owned_by: "axiom",
                supported_reasoning_efforts: m.supported_reasoning_efforts,
            })
            .collect(),
    }))
}

pub async fn healthz() -> impl IntoResponse {
    Json(serde_json::json!({ "ok": true }))
}
