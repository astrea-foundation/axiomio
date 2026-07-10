//! OpenAI-compatible request/response types for the local /v1 surface.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

pub const MAX_MESSAGES: usize = 101;
pub const MAX_TOOLS: usize = 128;
pub const MAX_TOOL_CALLS: usize = 128;
pub const MAX_TOOL_CALL_ID_CHARS: usize = 256;
pub const MAX_FUNCTION_NAME_CHARS: usize = 64;
pub const MAX_MESSAGE_TEXT_BYTES: usize = 262_000;
pub const MAX_TOOL_DESCRIPTION_BYTES: usize = 16_384;
pub const MAX_TOOL_PARAMETERS_BYTES: usize = 131_072;
pub const MAX_TOOL_ARGUMENTS_BYTES: usize = 262_000;
pub const MAX_FINISH_REASON_CHARS: usize = 64;
pub const MAX_RELAY_REQUEST_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(default)]
    pub stream: bool,
    #[serde(default)]
    pub stream_options: Option<StreamOptions>,
    #[serde(default, alias = "max_completion_tokens")]
    pub max_tokens: Option<u32>,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(default)]
    pub top_p: Option<f64>,
    #[serde(default)]
    pub frequency_penalty: Option<f64>,
    #[serde(default)]
    pub presence_penalty: Option<f64>,
    #[serde(default)]
    pub seed: Option<i64>,
    #[serde(default)]
    pub stop: Option<serde_json::Value>,
    #[serde(default)]
    pub logit_bias: Option<serde_json::Value>,
    #[serde(default)]
    pub response_format: Option<serde_json::Value>,
    #[serde(default)]
    pub reasoning_effort: Option<ReasoningEffort>,
    #[serde(default)]
    pub tools: Option<Vec<ToolDefinition>>,
    #[serde(default)]
    pub tool_choice: Option<ToolChoice>,
    #[serde(default)]
    pub parallel_tool_calls: Option<bool>,
    #[serde(default)]
    pub functions: Option<serde_json::Value>,
    #[serde(default)]
    pub function_call: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ReasoningEffort {
    Low,
    Medium,
    High,
    Xhigh,
}

impl ReasoningEffort {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Xhigh => "xhigh",
        }
    }
}

impl ChatRequest {
    pub fn sampling(&self) -> Option<serde_json::Value> {
        let mut map = serde_json::Map::new();
        macro_rules! put {
            ($k:literal, $v:expr) => {
                if let Some(v) = $v {
                    map.insert($k.into(), serde_json::json!(v));
                }
            };
        }
        put!("temperature", self.temperature);
        put!("top_p", self.top_p);
        put!("frequency_penalty", self.frequency_penalty);
        put!("presence_penalty", self.presence_penalty);
        put!("seed", self.seed);
        if let Some(stop) = &self.stop {
            map.insert("stop".into(), stop.clone());
        }
        if let Some(bias) = &self.logit_bias {
            map.insert("logit_bias".into(), bias.clone());
        }
        if map.is_empty() {
            None
        } else {
            Some(serde_json::Value::Object(map))
        }
    }

    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.model.is_empty() || self.model.len() > 200 {
            return Err("model must be between 1 and 200 characters".into());
        }
        if self.messages.is_empty() || self.messages.len() > MAX_MESSAGES {
            return Err(format!(
                "messages must contain between 1 and {MAX_MESSAGES} items"
            ));
        }
        if self.functions.is_some() || self.function_call.is_some() {
            return Err(
                "legacy functions/function_call inputs are not supported; use tools".into(),
            );
        }

        if let Some(tools) = &self.tools {
            if tools.is_empty() || tools.len() > MAX_TOOLS {
                return Err(format!(
                    "tools must contain between 1 and {MAX_TOOLS} items"
                ));
            }
            let mut names = HashSet::new();
            for tool in tools {
                tool.validate()?;
                if !names.insert(tool.function.name.as_str()) {
                    return Err("tool function names must be unique".into());
                }
            }
        }

        if let Some(choice) = &self.tool_choice {
            choice.validate(self.tools.as_deref())?;
        }
        if self.parallel_tool_calls.is_some() && self.tools.is_none() {
            return Err("parallel_tool_calls requires tools".into());
        }

        for (index, message) in self.messages.iter().enumerate() {
            message
                .validate()
                .map_err(|error| format!("messages[{index}]: {error}"))?;
        }
        Ok(())
    }

    pub fn requires_all_fields_encryption(&self) -> bool {
        self.tools.is_some()
            || matches!(self.tool_choice, Some(ToolChoice::Named(_)))
            || self.messages.iter().any(ChatMessage::has_all_fields_data)
    }
}

#[derive(Debug, Deserialize)]
pub struct StreamOptions {
    #[serde(default)]
    pub include_usage: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MessageRole {
    System,
    Developer,
    User,
    Assistant,
    Tool,
}

impl MessageRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Developer => "developer",
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::Tool => "tool",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ChatMessage {
    pub role: MessageRole,
    #[serde(default)]
    pub content: Option<MessageContent>,
    #[serde(default)]
    pub reasoning_content: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub refusal: Option<String>,
    #[serde(default)]
    pub tool_calls: Option<Vec<ToolCall>>,
    #[serde(default)]
    pub tool_call_id: Option<String>,
}

impl ChatMessage {
    pub fn content_text(&self) -> std::result::Result<Option<String>, String> {
        self.content
            .as_ref()
            .map(MessageContent::as_text)
            .transpose()
    }

    fn has_all_fields_data(&self) -> bool {
        self.role == MessageRole::Tool
            || self.tool_call_id.is_some()
            || self.name.is_some()
            || self.refusal.is_some()
            || self.tool_calls.is_some()
    }

    fn validate(&self) -> std::result::Result<(), String> {
        let content = self.content_text()?;
        if let Some(value) = &content {
            validate_bytes("content", value, MAX_MESSAGE_TEXT_BYTES)?;
        }
        if let Some(value) = &self.reasoning_content {
            validate_bytes("reasoning_content", value, MAX_MESSAGE_TEXT_BYTES)?;
        }
        if let Some(value) = &self.name {
            validate_identifier("name", value, MAX_FUNCTION_NAME_CHARS)?;
        }
        if let Some(value) = &self.refusal {
            validate_bytes("refusal", value, MAX_MESSAGE_TEXT_BYTES)?;
        }

        match self.role {
            MessageRole::System | MessageRole::Developer | MessageRole::User => {
                if content.is_none() {
                    return Err(
                        "content is required for system, developer, and user messages".into(),
                    );
                }
                if self.tool_calls.is_some()
                    || self.tool_call_id.is_some()
                    || self.refusal.is_some()
                {
                    return Err(
                        "tool_calls, tool_call_id, and refusal are invalid for this role".into(),
                    );
                }
                if self.reasoning_content.is_some() {
                    return Err("reasoning_content is only valid for assistant messages".into());
                }
            }
            MessageRole::Assistant => {
                if self.tool_call_id.is_some() {
                    return Err("tool_call_id is only valid for tool messages".into());
                }
                let has_tool_calls = self
                    .tool_calls
                    .as_ref()
                    .is_some_and(|tool_calls| !tool_calls.is_empty());
                if content.is_none() && !has_tool_calls && self.refusal.is_none() {
                    return Err("assistant message requires content, refusal, or tool_calls".into());
                }
                if let Some(tool_calls) = &self.tool_calls {
                    validate_tool_calls(tool_calls)?;
                }
            }
            MessageRole::Tool => {
                if content.is_none() {
                    return Err("content is required for tool messages".into());
                }
                let id = self
                    .tool_call_id
                    .as_deref()
                    .ok_or_else(|| "tool_call_id is required for tool messages".to_string())?;
                validate_tool_call_id(id)?;
                if self.tool_calls.is_some()
                    || self.refusal.is_some()
                    || self.reasoning_content.is_some()
                    || self.name.is_some()
                {
                    return Err(
                        "tool_calls, refusal, reasoning_content, and name are invalid for tool messages"
                            .into(),
                    );
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    Text(String),
    Parts(Vec<ContentPart>),
}

#[derive(Debug, Deserialize)]
pub struct ContentPart {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub text: Option<String>,
}

impl MessageContent {
    pub fn as_text(&self) -> std::result::Result<String, String> {
        match self {
            MessageContent::Text(value) => Ok(value.clone()),
            MessageContent::Parts(parts) => {
                let mut output = String::new();
                for part in parts {
                    if part.kind != "text" {
                        return Err(format!("unsupported content part type: {}", part.kind));
                    }
                    output.push_str(part.text.as_deref().unwrap_or(""));
                }
                Ok(output)
            }
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ToolDefinition {
    #[serde(rename = "type")]
    pub kind: String,
    pub function: FunctionDefinition,
}

impl ToolDefinition {
    fn validate(&self) -> std::result::Result<(), String> {
        if self.kind != "function" {
            return Err("only function tools are supported".into());
        }
        validate_identifier(
            "tool function name",
            &self.function.name,
            MAX_FUNCTION_NAME_CHARS,
        )?;
        if let Some(description) = &self.function.description {
            validate_bytes(
                "tool function description",
                description,
                MAX_TOOL_DESCRIPTION_BYTES,
            )?;
        }
        if !self.function.parameters.is_object() {
            return Err("tool function parameters must be a JSON object".into());
        }
        let parameters = serde_json::to_vec(&self.function.parameters)
            .map_err(|_| "tool function parameters could not be serialized")?;
        if parameters.len() > MAX_TOOL_PARAMETERS_BYTES {
            return Err(format!(
                "tool function parameters exceed {MAX_TOOL_PARAMETERS_BYTES} bytes"
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct FunctionDefinition {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub parameters: serde_json::Value,
    #[serde(default)]
    pub strict: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ToolChoice {
    Mode(String),
    Named(NamedToolChoice),
}

impl ToolChoice {
    fn validate(&self, tools: Option<&[ToolDefinition]>) -> std::result::Result<(), String> {
        match self {
            Self::Mode(mode) => {
                if !matches!(mode.as_str(), "auto" | "none" | "required") {
                    return Err(
                        "tool_choice must be auto, none, required, or a named function".into(),
                    );
                }
                if mode != "none" && tools.is_none() {
                    return Err("tool_choice requires tools".into());
                }
            }
            Self::Named(choice) => {
                if choice.kind != "function" {
                    return Err("named tool_choice type must be function".into());
                }
                validate_identifier(
                    "tool_choice function name",
                    &choice.function.name,
                    MAX_FUNCTION_NAME_CHARS,
                )?;
                let tools = tools.ok_or_else(|| "named tool_choice requires tools".to_string())?;
                if !tools
                    .iter()
                    .any(|tool| tool.function.name == choice.function.name)
                {
                    return Err("named tool_choice must reference a declared tool".into());
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct NamedToolChoice {
    #[serde(rename = "type")]
    pub kind: String,
    pub function: NamedFunction,
}

#[derive(Debug, Deserialize)]
pub struct NamedFunction {
    pub name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolCall {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub function: FunctionCall,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FunctionCall {
    pub name: String,
    pub arguments: String,
}

pub fn validate_tool_calls(tool_calls: &[ToolCall]) -> std::result::Result<(), String> {
    if tool_calls.is_empty() || tool_calls.len() > MAX_TOOL_CALLS {
        return Err(format!(
            "tool_calls must contain between 1 and {MAX_TOOL_CALLS} items"
        ));
    }
    let mut ids = HashSet::new();
    for tool_call in tool_calls {
        if tool_call.kind != "function" {
            return Err("only function tool_calls are supported".into());
        }
        validate_tool_call_id(&tool_call.id)?;
        if !ids.insert(tool_call.id.as_str()) {
            return Err("tool_call ids must be unique within a message".into());
        }
        validate_identifier(
            "tool_call function name",
            &tool_call.function.name,
            MAX_FUNCTION_NAME_CHARS,
        )?;
        validate_bytes(
            "tool_call function arguments",
            &tool_call.function.arguments,
            MAX_TOOL_ARGUMENTS_BYTES,
        )?;
    }
    Ok(())
}

pub fn validate_finish_reason(value: &str) -> std::result::Result<(), String> {
    if value.is_empty()
        || value.chars().count() > MAX_FINISH_REASON_CHARS
        || value.chars().any(char::is_control)
    {
        return Err(format!(
            "finish_reason must be 1-{MAX_FINISH_REASON_CHARS} non-control characters"
        ));
    }
    Ok(())
}

fn validate_tool_call_id(value: &str) -> std::result::Result<(), String> {
    if value.is_empty()
        || value.chars().count() > MAX_TOOL_CALL_ID_CHARS
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
    {
        return Err(format!(
            "tool_call_id must be 1-{MAX_TOOL_CALL_ID_CHARS} opaque ASCII characters"
        ));
    }
    Ok(())
}

fn validate_identifier(
    label: &str,
    value: &str,
    max_chars: usize,
) -> std::result::Result<(), String> {
    if value.is_empty()
        || value.chars().count() > max_chars
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(format!(
            "{label} must be 1-{max_chars} ASCII letters, digits, underscores, or hyphens"
        ));
    }
    Ok(())
}

fn validate_bytes(label: &str, value: &str, max_bytes: usize) -> std::result::Result<(), String> {
    if value.len() > max_bytes {
        return Err(format!("{label} exceeds {max_bytes} bytes"));
    }
    Ok(())
}

// ---- Responses ----

#[derive(Debug, Serialize)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

#[derive(Debug, Serialize)]
pub struct ChatCompletion {
    pub id: String,
    pub object: &'static str,
    pub created: u64,
    pub model: String,
    pub choices: Vec<Choice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
}

#[derive(Debug, Serialize)]
pub struct Choice {
    pub index: u32,
    pub message: AssistantMessage,
    pub finish_reason: String,
}

#[derive(Debug, Serialize)]
pub struct AssistantMessage {
    pub role: &'static str,
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
}

#[derive(Debug, Serialize)]
pub struct ChatChunk {
    pub id: String,
    pub object: &'static str,
    pub created: u64,
    pub model: String,
    pub choices: Vec<ChunkChoice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
}

#[derive(Debug, Serialize)]
pub struct ChunkChoice {
    pub index: u32,
    pub delta: Delta,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct Delta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCallDelta>>,
}

#[derive(Debug, Serialize)]
pub struct ToolCallDelta {
    pub index: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<FunctionCallDelta>,
}

#[derive(Debug, Serialize)]
pub struct FunctionCallDelta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub error: ApiErrorBody,
}

#[derive(Debug, Serialize)]
pub struct ApiErrorBody {
    pub message: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

impl ApiError {
    pub fn new(kind: &str, message: impl Into<String>) -> Self {
        Self {
            error: ApiErrorBody {
                message: message.into(),
                kind: kind.into(),
                code: None,
            },
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ModelList {
    pub object: &'static str,
    pub data: Vec<ModelEntry>,
}

#[derive(Debug, Serialize)]
pub struct ModelEntry {
    pub id: String,
    pub object: &'static str,
    pub owned_by: &'static str,
    pub supported_reasoning_efforts: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(json: serde_json::Value) -> ChatRequest {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn sampling_collects_present_params_only() {
        let request = req(serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "hi"}],
            "temperature": 0.4,
            "stop": ["\n"],
            "logit_bias": {"5": -10}
        }));
        let sampling = request.sampling().unwrap();
        assert_eq!(sampling["temperature"], 0.4);
        assert_eq!(sampling["stop"], serde_json::json!(["\n"]));
        assert_eq!(sampling["logit_bias"], serde_json::json!({"5": -10}));
        assert!(sampling.get("top_p").is_none());
    }

    #[test]
    fn sampling_is_none_when_absent() {
        let request = req(serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "hi"}]
        }));
        assert!(request.sampling().is_none());
    }

    #[test]
    fn reasoning_effort_accepts_only_closed_openai_values() {
        for value in ["low", "medium", "high", "xhigh"] {
            let request = req(serde_json::json!({
                "model": "m",
                "messages": [{"role": "user", "content": "hi"}],
                "reasoning_effort": value
            }));
            assert_eq!(request.reasoning_effort.unwrap().as_str(), value);
            assert!(request.sampling().is_none());
        }

        let invalid: Result<ChatRequest, _> = serde_json::from_value(serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "hi"}],
            "reasoning_effort": "unbounded"
        }));
        assert!(invalid.is_err());
    }

    #[test]
    fn content_parts_flatten_and_reject_non_text() {
        let text = req(serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}]
        }));
        assert_eq!(
            text.messages[0].content_text().unwrap().as_deref(),
            Some("hi")
        );

        let image = req(serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": [{"type": "image_url"}]}]
        }));
        assert!(image.messages[0].content_text().is_err());
    }

    #[test]
    fn opencode_fixture_covers_initial_and_post_tool_requests() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/opencode/tool-loop-v1.17.18.json"
        ))
        .unwrap();
        for key in ["initial_request", "request_after_tool"] {
            let request: ChatRequest = serde_json::from_value(fixture[key].clone()).unwrap();
            request.validate().unwrap();
            assert!(request.requires_all_fields_encryption());
        }
        let request: ChatRequest =
            serde_json::from_value(fixture["request_after_tool"].clone()).unwrap();
        assert_eq!(request.messages[2].role, MessageRole::Assistant);
        assert_eq!(request.messages[3].role, MessageRole::Tool);
    }

    #[test]
    fn assistant_null_content_with_tool_call_is_valid() {
        let request = req(serde_json::json!({
            "model": "m",
            "messages": [
                {"role": "user", "content": "hi"},
                {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "read", "arguments": "{}"}
                    }]
                },
                {"role": "tool", "tool_call_id": "call_1", "content": "ok"}
            ],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "read",
                    "description": "read",
                    "parameters": {"type": "object"}
                }
            }]
        }));
        request.validate().unwrap();
    }

    #[test]
    fn rejects_legacy_and_invalid_role_shapes() {
        let legacy = req(serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "hi"}],
            "functions": []
        }));
        assert!(legacy.validate().unwrap_err().contains("legacy"));

        let missing_tool_id = req(serde_json::json!({
            "model": "m",
            "messages": [{"role": "tool", "content": "result"}]
        }));
        assert!(missing_tool_id
            .validate()
            .unwrap_err()
            .contains("tool_call_id"));
    }

    #[test]
    fn assistant_response_serializes_null_content_and_tool_calls() {
        let message = AssistantMessage {
            role: "assistant",
            content: None,
            reasoning_content: None,
            refusal: None,
            tool_calls: Some(vec![ToolCall {
                id: "call_1".into(),
                kind: "function".into(),
                function: FunctionCall {
                    name: "read".into(),
                    arguments: "{}".into(),
                },
            }]),
        };
        let value = serde_json::to_value(message).unwrap();
        assert!(value["content"].is_null());
        assert_eq!(value["tool_calls"][0]["function"]["name"], "read");
    }

    #[test]
    fn tool_role_alone_requires_all_fields_encryption() {
        let request = req(serde_json::json!({
            "model": "m",
            "messages": [{
                "role": "tool",
                "tool_call_id": "call_1",
                "content": "result"
            }]
        }));
        request.validate().unwrap();
        assert!(request.requires_all_fields_encryption());
    }

    #[test]
    fn validates_every_configured_count_and_length_boundary() {
        assert!(validate_identifier("name", &"a".repeat(MAX_FUNCTION_NAME_CHARS), 64).is_ok());
        assert!(validate_identifier("name", &"a".repeat(MAX_FUNCTION_NAME_CHARS + 1), 64).is_err());
        assert!(validate_tool_call_id(&"a".repeat(MAX_TOOL_CALL_ID_CHARS)).is_ok());
        assert!(validate_tool_call_id(&"a".repeat(MAX_TOOL_CALL_ID_CHARS + 1)).is_err());
        assert!(validate_bytes(
            "content",
            &"a".repeat(MAX_MESSAGE_TEXT_BYTES),
            MAX_MESSAGE_TEXT_BYTES
        )
        .is_ok());
        assert!(validate_bytes(
            "content",
            &"a".repeat(MAX_MESSAGE_TEXT_BYTES + 1),
            MAX_MESSAGE_TEXT_BYTES
        )
        .is_err());
        assert!(validate_bytes(
            "description",
            &"a".repeat(MAX_TOOL_DESCRIPTION_BYTES),
            MAX_TOOL_DESCRIPTION_BYTES
        )
        .is_ok());
        assert!(validate_bytes(
            "description",
            &"a".repeat(MAX_TOOL_DESCRIPTION_BYTES + 1),
            MAX_TOOL_DESCRIPTION_BYTES
        )
        .is_err());
        assert!(validate_bytes(
            "arguments",
            &"a".repeat(MAX_TOOL_ARGUMENTS_BYTES),
            MAX_TOOL_ARGUMENTS_BYTES
        )
        .is_ok());
        assert!(validate_bytes(
            "arguments",
            &"a".repeat(MAX_TOOL_ARGUMENTS_BYTES + 1),
            MAX_TOOL_ARGUMENTS_BYTES
        )
        .is_err());
        assert!(validate_finish_reason(&"a".repeat(MAX_FINISH_REASON_CHARS)).is_ok());
        assert!(validate_finish_reason(&"a".repeat(MAX_FINISH_REASON_CHARS + 1)).is_err());
        assert!(validate_finish_reason("bad\nreason").is_err());

        let tool_calls = (0..MAX_TOOL_CALLS)
            .map(|index| ToolCall {
                id: format!("call_{index}"),
                kind: "function".into(),
                function: FunctionCall {
                    name: "read".into(),
                    arguments: "{}".into(),
                },
            })
            .collect::<Vec<_>>();
        assert!(validate_tool_calls(&tool_calls).is_ok());
        let mut too_many_calls = tool_calls;
        too_many_calls.push(ToolCall {
            id: "call_over".into(),
            kind: "function".into(),
            function: FunctionCall {
                name: "read".into(),
                arguments: "{}".into(),
            },
        });
        assert!(validate_tool_calls(&too_many_calls).is_err());

        let parameters_at_limit = serde_json::json!({
            "x": "a".repeat(MAX_TOOL_PARAMETERS_BYTES - 8)
        });
        let parameters_over_limit = serde_json::json!({
            "x": "a".repeat(MAX_TOOL_PARAMETERS_BYTES - 7)
        });
        assert_eq!(
            serde_json::to_vec(&parameters_at_limit).unwrap().len(),
            MAX_TOOL_PARAMETERS_BYTES
        );
        assert_eq!(
            serde_json::to_vec(&parameters_over_limit).unwrap().len(),
            MAX_TOOL_PARAMETERS_BYTES + 1
        );
        let at_limit = ToolDefinition {
            kind: "function".into(),
            function: FunctionDefinition {
                name: "read".into(),
                description: None,
                parameters: parameters_at_limit,
                strict: None,
            },
        };
        let over_limit = ToolDefinition {
            kind: "function".into(),
            function: FunctionDefinition {
                name: "read".into(),
                description: None,
                parameters: parameters_over_limit,
                strict: None,
            },
        };
        assert!(at_limit.validate().is_ok());
        assert!(over_limit.validate().is_err());
    }

    #[test]
    fn validates_message_and_tool_count_boundaries() {
        let messages = (0..MAX_MESSAGES)
            .map(|_| serde_json::json!({"role": "user", "content": "x"}))
            .collect::<Vec<_>>();
        let at_message_limit = req(serde_json::json!({"model": "m", "messages": messages}));
        assert!(at_message_limit.validate().is_ok());
        let too_many_messages = (0..=MAX_MESSAGES)
            .map(|_| serde_json::json!({"role": "user", "content": "x"}))
            .collect::<Vec<_>>();
        let over_message_limit = req(serde_json::json!({
            "model": "m",
            "messages": too_many_messages
        }));
        assert!(over_message_limit.validate().is_err());

        let tools = (0..MAX_TOOLS)
            .map(|index| {
                serde_json::json!({
                    "type": "function",
                    "function": {
                        "name": format!("tool_{index}"),
                        "parameters": {"type": "object"}
                    }
                })
            })
            .collect::<Vec<_>>();
        let at_tool_limit = req(serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "x"}],
            "tools": tools
        }));
        assert!(at_tool_limit.validate().is_ok());
        let too_many_tools = (0..=MAX_TOOLS)
            .map(|index| {
                serde_json::json!({
                    "type": "function",
                    "function": {
                        "name": format!("tool_{index}"),
                        "parameters": {"type": "object"}
                    }
                })
            })
            .collect::<Vec<_>>();
        let over_tool_limit = req(serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "x"}],
            "tools": too_many_tools
        }));
        assert!(over_tool_limit.validate().is_err());
    }
}
