//! Exact-once terminal audit recording for one parsed chat-completions request.

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axiom_core::events::{
    E2eeAuditReceipt, RequestLogEntry, RequestTerminalStatus, TeeAuditReceipt,
};

use crate::state::ProxyCore;

pub struct RequestSecurityReceipt {
    pub model: String,
    pub provider: String,
    pub e2ee: E2eeAuditReceipt,
    pub tee: TeeAuditReceipt,
}

/// Owns the active-request counter and writes exactly one terminal metadata record. Once handed to
/// the streaming response body, dropping the body before a terminal provider event is recorded as
/// a client cancellation.
pub struct RequestAudit {
    core: Arc<ProxyCore>,
    id: String,
    model: String,
    provider: String,
    stream: bool,
    started_at_unix_ms: u64,
    started: Instant,
    e2ee: E2eeAuditReceipt,
    tee: TeeAuditReceipt,
    terminal: bool,
    cancel_on_drop: bool,
}

impl RequestAudit {
    pub fn start(core: Arc<ProxyCore>, id: String, requested_model: String, stream: bool) -> Self {
        core.record_start();
        Self {
            core,
            id,
            model: requested_model,
            provider: "unknown".into(),
            stream,
            started_at_unix_ms: now_unix_ms(),
            started: Instant::now(),
            e2ee: E2eeAuditReceipt::default(),
            tee: TeeAuditReceipt::default(),
            terminal: false,
            cancel_on_drop: false,
        }
    }

    pub fn set_security(&mut self, receipt: RequestSecurityReceipt) {
        self.model = receipt.model;
        self.provider = receipt.provider;
        self.e2ee = receipt.e2ee;
        self.tee = receipt.tee;
    }

    pub fn backend_key_accepted(&mut self) {
        self.e2ee.backend_key_accepted = true;
    }

    pub fn response_decrypted(&mut self) {
        self.e2ee.response_decrypted = true;
    }

    pub fn cancel_if_dropped(&mut self) {
        self.cancel_on_drop = true;
    }

    pub fn complete(&mut self, prompt_tokens: u32, completion_tokens: u32, finish_reason: String) {
        self.finish(
            RequestTerminalStatus::Completed,
            prompt_tokens,
            completion_tokens,
            Some(finish_reason),
            None,
        );
    }

    pub fn fail(&mut self, error_kind: impl Into<String>) {
        self.finish(
            RequestTerminalStatus::Failed,
            0,
            0,
            None,
            Some(error_kind.into()),
        );
    }

    pub fn fail_with_usage(
        &mut self,
        error_kind: impl Into<String>,
        prompt_tokens: u32,
        completion_tokens: u32,
    ) {
        self.finish(
            RequestTerminalStatus::Failed,
            prompt_tokens,
            completion_tokens,
            None,
            Some(error_kind.into()),
        );
    }

    pub fn cancel(&mut self, error_kind: impl Into<String>) {
        self.finish(
            RequestTerminalStatus::Cancelled,
            0,
            0,
            None,
            Some(error_kind.into()),
        );
    }

    fn finish(
        &mut self,
        status: RequestTerminalStatus,
        prompt_tokens: u32,
        completion_tokens: u32,
        finish_reason: Option<String>,
        error_kind: Option<String>,
    ) {
        if self.terminal {
            return;
        }
        self.terminal = true;
        self.core.record_finish(prompt_tokens, completion_tokens);
        self.core.log_request(RequestLogEntry {
            id: self.id.clone(),
            model: self.model.clone(),
            provider: self.provider.clone(),
            stream: self.stream,
            status,
            started_at_unix_ms: self.started_at_unix_ms,
            completed_at_unix_ms: now_unix_ms(),
            prompt_tokens,
            completion_tokens,
            duration_ms: self.started.elapsed().as_millis() as u64,
            finish_reason,
            error_kind,
            e2ee: self.e2ee.clone(),
            tee: self.tee.clone(),
        });
    }
}

impl Drop for RequestAudit {
    fn drop(&mut self) {
        if !self.terminal {
            if self.cancel_on_drop {
                self.cancel("client_disconnected");
            } else {
                self.fail("request_incomplete");
            }
        }
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
