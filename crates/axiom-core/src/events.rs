//! Events and status snapshots the server publishes for the UI. Kept Tauri-free so the headless
//! binary can drop them; the Tauri shell forwards them to the webview.

use serde::{Deserialize, Serialize};

use crate::provider::VerificationCheck;
use crate::providers::near::{NEAR_V2_ENCRYPTION_VERSION, NEAR_V2_PROTOCOL};

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum RequestPhase {
    Started,
    Attesting,
    Streaming,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestEvent {
    pub id: String,
    pub phase: RequestPhase,
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
}

/// Metadata-only request-log entry (never message content).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestTerminalStatus {
    Completed,
    Failed,
    Cancelled,
}

/// Metadata proving which encrypted request path was used. Booleans deliberately describe
/// individual lifecycle facts so the UI only labels a request fully verified when all of them and
/// the terminal `completed` status are present.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct E2eeAuditReceipt {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_version: Option<u8>,
    pub request_encrypted: bool,
    pub backend_key_accepted: bool,
    pub response_decrypted: bool,
    pub ephemeral_client_key: bool,
}

/// Metadata copied from the exact locally verified attestation used by a request. The model key is
/// represented only by a SHA-256 fingerprint; full key material is never part of an audit record.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct TeeAuditReceipt {
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at_unix_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_key_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_spki_sha256: Option<String>,
    #[serde(default)]
    pub checks: Vec<VerificationCheck>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RequestLogEntry {
    pub id: String,
    pub model: String,
    pub provider: String,
    pub stream: bool,
    pub status: RequestTerminalStatus,
    pub started_at_unix_ms: u64,
    pub completed_at_unix_ms: u64,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    pub e2ee: E2eeAuditReceipt,
    pub tee: TeeAuditReceipt,
}

impl RequestLogEntry {
    /// `true` means the request reached a valid encrypted terminal completion. It is intentionally
    /// stricter than checking only the E2EE protocol label.
    pub fn verified_completed(&self) -> bool {
        self.status == RequestTerminalStatus::Completed
            && self.tee.verified
            && self.e2ee.request_encrypted
            && self.e2ee.backend_key_accepted
            && self.e2ee.response_decrypted
            && self.e2ee.ephemeral_client_key
            && self.e2ee.protocol.as_deref() == Some(NEAR_V2_PROTOCOL)
            && self.e2ee.encryption_version == Some(NEAR_V2_ENCRYPTION_VERSION)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn completed_receipt() -> RequestLogEntry {
        RequestLogEntry {
            id: "request-1".into(),
            model: "glm-5-2".into(),
            provider: "near".into(),
            stream: true,
            status: RequestTerminalStatus::Completed,
            started_at_unix_ms: 1,
            completed_at_unix_ms: 2,
            prompt_tokens: 3,
            completion_tokens: 4,
            duration_ms: 1,
            finish_reason: Some("stop".into()),
            error_kind: None,
            e2ee: E2eeAuditReceipt {
                protocol: Some(NEAR_V2_PROTOCOL.into()),
                encryption_version: Some(NEAR_V2_ENCRYPTION_VERSION),
                request_encrypted: true,
                backend_key_accepted: true,
                response_decrypted: true,
                ephemeral_client_key: true,
            },
            tee: TeeAuditReceipt {
                verified: true,
                ..Default::default()
            },
        }
    }

    #[test]
    fn verified_completion_requires_exact_near_v2_evidence() {
        let entry = completed_receipt();
        assert!(entry.verified_completed());

        let mut wrong_protocol = entry.clone();
        wrong_protocol.e2ee.protocol = Some("near-v3".into());
        assert!(!wrong_protocol.verified_completed());

        let mut wrong_version = entry.clone();
        wrong_version.e2ee.encryption_version = Some(1);
        assert!(!wrong_version.verified_completed());

        let mut failed = entry;
        failed.status = RequestTerminalStatus::Failed;
        assert!(!failed.verified_completed());
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AttestationSummary {
    pub model_id: String,
    pub base_url: String,
    pub provider: String,
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_pubkey_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_fingerprint: Option<String>,
    /// Ordered provider-specific checks; empty when verification failed before any ran.
    pub checks: Vec<VerificationCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
