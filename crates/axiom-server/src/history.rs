//! Restart-durable, metadata-only request history.

use std::collections::VecDeque;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use axiom_core::events::RequestLogEntry;
use serde::{Deserialize, Serialize};

pub const REQUEST_HISTORY_CAP: usize = 100;
const REQUEST_HISTORY_VERSION: u8 = 1;

#[derive(Debug, Deserialize, Serialize)]
struct HistoryDocument {
    version: u8,
    entries: Vec<RequestLogEntry>,
}

/// The in-memory deque is authoritative while the proxy is running. Persistence is best-effort:
/// an I/O failure is reported to the runtime log but can never alter inference routing or relax
/// attestation/E2EE checks.
pub struct RequestHistory {
    path: Option<PathBuf>,
    entries: VecDeque<RequestLogEntry>,
}

impl RequestHistory {
    pub fn memory_only() -> Self {
        Self {
            path: None,
            entries: VecDeque::with_capacity(REQUEST_HISTORY_CAP),
        }
    }

    pub fn load(path: PathBuf) -> Self {
        let entries = match Self::read_document(&path) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => VecDeque::new(),
            Err(error) => {
                tracing::warn!(
                    target: "axiom.request_audit",
                    history_path = %path.display(),
                    error_kind = ?error.kind(),
                    "request history could not be loaded; starting with an empty metadata log"
                );
                VecDeque::new()
            }
        };
        Self {
            path: Some(path),
            entries,
        }
    }

    fn read_document(path: &Path) -> io::Result<VecDeque<RequestLogEntry>> {
        let bytes = fs::read(path)?;
        let document: HistoryDocument = serde_json::from_slice(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if document.version != REQUEST_HISTORY_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported request history version {}", document.version),
            ));
        }
        Ok(document
            .entries
            .into_iter()
            .rev()
            .take(REQUEST_HISTORY_CAP)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect())
    }

    pub fn push(&mut self, entry: RequestLogEntry) -> io::Result<()> {
        if self.entries.len() == REQUEST_HISTORY_CAP {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
        self.persist()
    }

    pub fn recent(&self, limit: usize) -> Vec<RequestLogEntry> {
        self.entries
            .iter()
            .rev()
            .take(limit.min(REQUEST_HISTORY_CAP))
            .cloned()
            .collect()
    }

    fn persist(&self) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let document = HistoryDocument {
            version: REQUEST_HISTORY_VERSION,
            entries: self.entries.iter().cloned().collect(),
        };
        let bytes = serde_json::to_vec_pretty(&document)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let mut temporary = tempfile::Builder::new()
            .prefix(".request-history-")
            .tempfile_in(parent)?;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        temporary.persist(path).map_err(|error| error.error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_core::events::{E2eeAuditReceipt, RequestTerminalStatus, TeeAuditReceipt};
    use axiom_core::provider::VerificationCheck;

    fn entry(index: usize) -> RequestLogEntry {
        RequestLogEntry {
            id: format!("request-{index}"),
            model: "glm-5-2".into(),
            provider: "near".into(),
            stream: true,
            status: RequestTerminalStatus::Completed,
            started_at_unix_ms: index as u64,
            completed_at_unix_ms: index as u64 + 1,
            prompt_tokens: index as u32,
            completion_tokens: 2,
            duration_ms: 1,
            finish_reason: Some("stop".into()),
            error_kind: None,
            e2ee: E2eeAuditReceipt {
                protocol: Some("near-v2".into()),
                encryption_version: Some(2),
                request_encrypted: true,
                backend_key_accepted: true,
                response_decrypted: true,
                ephemeral_client_key: true,
            },
            tee: TeeAuditReceipt {
                verified: true,
                verified_at_unix_ms: Some(1),
                age_ms: Some(0),
                model_key_sha256: Some("ab".repeat(32)),
                tls_spki_sha256: Some("cd".repeat(32)),
                checks: vec![VerificationCheck::new(
                    "intel_tdx",
                    "Intel TDX",
                    "UpToDate",
                    true,
                )],
            },
        }
    }

    #[test]
    fn persists_reloads_and_caps_to_newest_hundred() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.json");
        let mut history = RequestHistory::load(path.clone());
        for index in 0..105 {
            history.push(entry(index)).unwrap();
        }
        assert_eq!(history.recent(200).len(), REQUEST_HISTORY_CAP);
        assert_eq!(history.recent(1)[0].id, "request-104");
        assert_eq!(history.recent(100).last().unwrap().id, "request-5");

        let reloaded = RequestHistory::load(path);
        assert_eq!(reloaded.recent(200), history.recent(200));
    }

    #[test]
    fn corrupt_file_starts_empty_without_overwriting_until_a_record_arrives() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.json");
        fs::write(&path, b"not-json").unwrap();
        let history = RequestHistory::load(path.clone());
        assert!(history.recent(100).is_empty());
        assert_eq!(fs::read(&path).unwrap(), b"not-json");
    }

    #[test]
    fn persisted_document_contains_metadata_but_no_message_fields_or_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.json");
        let mut history = RequestHistory::load(path.clone());
        history.push(entry(1)).unwrap();
        let text = fs::read_to_string(path).unwrap();
        assert!(text.contains("near-v2"));
        assert!(text.contains("model_key_sha256"));
        for forbidden in [
            "plaintext-sentinel",
            "encrypted_messages",
            "ciphertext",
            "client_public_key",
            "model_public_key_hex",
            "api_key",
            "tool_arguments",
        ] {
            assert!(
                !text.contains(forbidden),
                "history leaked forbidden field {forbidden}"
            );
        }
    }

    #[test]
    fn memory_only_history_never_writes() {
        let mut history = RequestHistory::memory_only();
        history.push(entry(1)).unwrap();
        assert_eq!(history.recent(1)[0].id, "request-1");
    }
}
