//! Translate an Axiom relay stream into OpenAI chat completion SSE locally.

use std::collections::HashSet;

use axiom_core::openai::{
    validate_finish_reason, ChatChunk, ChunkChoice, Delta, FunctionCallDelta, ToolCallDelta, Usage,
    MAX_TOOL_CALLS,
};
use axiom_core::provider::CipherSession;
use axiom_core::relay::{RelayEvent, RelayStream};
use axum::response::sse::Event;
use futures_util::StreamExt;

use crate::audit::RequestAudit;

fn chunk(id: &str, model: &str, created: u64, delta: Delta, finish: Option<&str>) -> ChatChunk {
    ChatChunk {
        id: id.to_string(),
        object: "chat.completion.chunk",
        created,
        model: model.to_string(),
        choices: vec![ChunkChoice {
            index: 0,
            delta,
            finish_reason: finish.map(String::from),
        }],
        usage: None,
    }
}

fn to_event<T: serde::Serialize>(value: &T) -> Event {
    Event::default().data(serde_json::to_string(value).unwrap_or_default())
}

fn decrypt_utf8(session: &mut dyn CipherSession, wire: &str) -> Option<String> {
    session
        .decrypt(wire)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

fn valid_tool_call_id(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

pub fn openai_stream(
    mut audit: RequestAudit,
    mut session: Box<dyn CipherSession>,
    mut relay: RelayStream,
    id: String,
    model: String,
    created: u64,
    include_usage: bool,
) -> impl futures_util::Stream<Item = std::result::Result<Event, std::convert::Infallible>> {
    async_stream::stream! {
        yield Ok(to_event(&chunk(
            &id,
            &model,
            created,
            Delta { role: Some("assistant"), ..Default::default() },
            None,
        )));

        let mut prompt_tokens = 0u32;
        let mut completion_tokens = 0u32;

        while let Some(item) = relay.next().await {
            match item {
                Ok(RelayEvent::Delta {
                    content,
                    reasoning,
                    refusal,
                    tool_calls,
                    ..
                }) => {
                    let mut delta = Delta::default();
                    if let Some(wire) = content {
                        match decrypt_utf8(session.as_mut(), &wire) {
                            Some(value) => {
                                audit.response_decrypted();
                                delta.content = Some(value);
                            }
                            None => {
                                audit.fail("decryption_error");
                                yield Ok(to_event(&serde_json::json!({
                                    "error": {"message": "failed to decrypt provider delta", "type": "decryption_error"}
                                })));
                                yield Ok(Event::default().data("[DONE]"));
                                return;
                            }
                        }
                    }
                    if let Some(wire) = reasoning {
                        match decrypt_utf8(session.as_mut(), &wire) {
                            Some(value) => {
                                audit.response_decrypted();
                                delta.reasoning_content = Some(value);
                            }
                            None => {
                                audit.fail("decryption_error");
                                yield Ok(to_event(&serde_json::json!({
                                    "error": {"message": "failed to decrypt provider reasoning delta", "type": "decryption_error"}
                                })));
                                yield Ok(Event::default().data("[DONE]"));
                                return;
                            }
                        }
                    }
                    if let Some(wire) = refusal {
                        match decrypt_utf8(session.as_mut(), &wire) {
                            Some(value) => {
                                audit.response_decrypted();
                                delta.refusal = Some(value);
                            }
                            None => {
                                audit.fail("decryption_error");
                                yield Ok(to_event(&serde_json::json!({
                                    "error": {"message": "failed to decrypt provider refusal delta", "type": "decryption_error"}
                                })));
                                yield Ok(Event::default().data("[DONE]"));
                                return;
                            }
                        }
                    }

                    if tool_calls.len() > MAX_TOOL_CALLS {
                        audit.fail("upstream_error");
                        yield Ok(to_event(&serde_json::json!({
                            "error": {"message": "provider returned too many tool-call deltas", "type": "upstream_error"}
                        })));
                        yield Ok(Event::default().data("[DONE]"));
                        return;
                    }
                    let mut seen_indexes = HashSet::new();
                    let mut decrypted_tool_calls = Vec::with_capacity(tool_calls.len());
                    for tool_call in tool_calls {
                        if tool_call.index as usize >= MAX_TOOL_CALLS
                            || !seen_indexes.insert(tool_call.index)
                            || tool_call.id.as_deref().is_some_and(|id| !valid_tool_call_id(id))
                            || tool_call.kind.as_deref().is_some_and(|kind| kind != "function")
                        {
                            audit.fail("upstream_error");
                            yield Ok(to_event(&serde_json::json!({
                                "error": {"message": "invalid provider tool-call delta metadata", "type": "upstream_error"}
                            })));
                            yield Ok(Event::default().data("[DONE]"));
                            return;
                        }
                        let function = if let Some(function) = tool_call.function {
                            let name = match function.encrypted_name {
                                Some(wire) => match decrypt_utf8(session.as_mut(), &wire) {
                                    Some(value) => {
                                        audit.response_decrypted();
                                        Some(value)
                                    }
                                    None => {
                                        audit.fail("decryption_error");
                                        yield Ok(to_event(&serde_json::json!({
                                            "error": {"message": "failed to decrypt provider tool-call name", "type": "decryption_error"}
                                        })));
                                        yield Ok(Event::default().data("[DONE]"));
                                        return;
                                    }
                                },
                                None => None,
                            };
                            let arguments = match function.encrypted_arguments {
                                Some(wire) => match decrypt_utf8(session.as_mut(), &wire) {
                                    Some(value) => {
                                        audit.response_decrypted();
                                        Some(value)
                                    }
                                    None => {
                                        audit.fail("decryption_error");
                                        yield Ok(to_event(&serde_json::json!({
                                            "error": {"message": "failed to decrypt provider tool-call arguments", "type": "decryption_error"}
                                        })));
                                        yield Ok(Event::default().data("[DONE]"));
                                        return;
                                    }
                                },
                                None => None,
                            };
                            Some(FunctionCallDelta { name, arguments })
                        } else {
                            None
                        };
                        decrypted_tool_calls.push(ToolCallDelta {
                            index: tool_call.index,
                            id: tool_call.id,
                            kind: tool_call.kind,
                            function,
                        });
                    }
                    if !decrypted_tool_calls.is_empty() {
                        delta.tool_calls = Some(decrypted_tool_calls);
                    }
                    if delta.content.is_some()
                        || delta.reasoning_content.is_some()
                        || delta.refusal.is_some()
                        || delta.tool_calls.is_some()
                    {
                        yield Ok(to_event(&chunk(&id, &model, created, delta, None)));
                    }
                }
                Ok(RelayEvent::Completed {
                    usage,
                    finish_reason,
                }) => {
                    prompt_tokens = usage.prompt_tokens.unwrap_or(0);
                    completion_tokens = usage.completion_tokens.unwrap_or(0);
                    let finish_reason = finish_reason.unwrap_or_else(|| "stop".to_string());
                    if validate_finish_reason(&finish_reason).is_err() {
                        audit.fail_with_usage(
                            "upstream_error",
                            prompt_tokens,
                            completion_tokens,
                        );
                        yield Ok(to_event(&serde_json::json!({
                            "error": {"message": "invalid provider finish_reason", "type": "upstream_error"}
                        })));
                        yield Ok(Event::default().data("[DONE]"));
                        return;
                    }
                    yield Ok(to_event(&chunk(
                        &id,
                        &model,
                        created,
                        Delta::default(),
                        Some(&finish_reason),
                    )));
                    if include_usage {
                        let usage_chunk = ChatChunk {
                            id: id.clone(),
                            object: "chat.completion.chunk",
                            created,
                            model: model.clone(),
                            choices: vec![],
                            usage: Some(Usage {
                                prompt_tokens,
                                completion_tokens,
                                total_tokens: usage.total_tokens.unwrap_or(0),
                            }),
                        };
                        yield Ok(to_event(&usage_chunk));
                    }
                    audit.complete(prompt_tokens, completion_tokens, finish_reason);
                    yield Ok(Event::default().data("[DONE]"));
                    return;
                }
                Ok(RelayEvent::Cancelled { reason }) => {
                    let message = reason.unwrap_or_else(|| "cancelled".into());
                    audit.cancel("relay_cancelled");
                    yield Ok(to_event(&serde_json::json!({
                        "error": {"message": message, "type": "cancelled", "code": "insufficient_credit"}
                    })));
                    yield Ok(Event::default().data("[DONE]"));
                    return;
                }
                Ok(RelayEvent::Failed { error }) => {
                    audit.fail_with_usage("upstream_error", prompt_tokens, completion_tokens);
                    yield Ok(to_event(&serde_json::json!({
                        "error": {"message": error, "type": "upstream_error"}
                    })));
                    yield Ok(Event::default().data("[DONE]"));
                    return;
                }
                Err(error) => {
                    audit.fail_with_usage("relay_error", prompt_tokens, completion_tokens);
                    yield Ok(to_event(&serde_json::json!({
                        "error": {"message": error.to_string(), "type": "relay_error"}
                    })));
                    yield Ok(Event::default().data("[DONE]"));
                    return;
                }
            }
        }

        audit.fail_with_usage(
            "stream_ended_without_completion",
            prompt_tokens,
            completion_tokens,
        );
        yield Ok(Event::default().data("[DONE]"));
    }
}
