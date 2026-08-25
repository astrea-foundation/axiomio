//! Shared proxy state: config snapshot, API key, relay client, attestation cache, and live
//! status/counters. Tauri-free so `--headless` mode and tests use it directly.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axiom_core::error::{CoreError, Result};
use axiom_core::events::RequestLogEntry;
use axiom_core::provider::{AttestationRequest, ProviderRegistry, VerifiedModel};
use axiom_core::relay::{RelayApi, RelayModel};
use tokio::sync::Mutex as AsyncMutex;

use crate::history::RequestHistory;

#[derive(Default)]
pub struct Counters {
    pub total_requests: AtomicU64,
    pub active_requests: AtomicU32,
    pub prompt_tokens: AtomicU64,
    pub completion_tokens: AtomicU64,
}

struct CachedAttestation {
    verified: Arc<VerifiedModel>,
    at: Instant,
    verified_at_unix_ms: u64,
}

#[derive(Clone)]
pub struct AttestationReceipt {
    pub verified: Arc<VerifiedModel>,
    pub verified_at_unix_ms: u64,
    pub age_ms: u64,
}

pub struct ProxyCore {
    pub relay: Arc<dyn RelayApi>,
    pub registry: Arc<ProviderRegistry>,
    pub attestation_ttl: Duration,
    pub default_model: Option<String>,
    api_key: RwLock<Option<String>>,
    models: RwLock<Vec<RelayModel>>,
    attestations: RwLock<HashMap<String, CachedAttestation>>,
    // Per-model single-flight so N concurrent requests trigger at most one verification.
    inflight: RwLock<HashMap<String, Arc<AsyncMutex<()>>>>,
    pub counters: Counters,
    // Metadata-only newest-100 history (never message content).
    request_log: RwLock<RequestHistory>,
}

impl ProxyCore {
    fn cached_attestation_is_fresh(&self, entry: &CachedAttestation) -> bool {
        entry.at.elapsed() < self.attestation_ttl
            && entry
                .verified
                .expires_at_unix
                .is_none_or(|expires| expires > current_unix_seconds())
    }

    pub fn new(
        relay: Arc<dyn RelayApi>,
        api_key: Option<String>,
        attestation_ttl: Duration,
        default_model: Option<String>,
    ) -> Self {
        Self::new_with_history(relay, api_key, attestation_ttl, default_model, None)
    }

    pub fn new_with_history(
        relay: Arc<dyn RelayApi>,
        api_key: Option<String>,
        attestation_ttl: Duration,
        default_model: Option<String>,
        history_path: Option<PathBuf>,
    ) -> Self {
        Self {
            relay,
            registry: Arc::new(ProviderRegistry::builtin()),
            attestation_ttl,
            default_model,
            api_key: RwLock::new(api_key),
            models: RwLock::new(Vec::new()),
            attestations: RwLock::new(HashMap::new()),
            inflight: RwLock::new(HashMap::new()),
            counters: Counters::default(),
            request_log: RwLock::new(match history_path {
                Some(path) => RequestHistory::load(path),
                None => RequestHistory::memory_only(),
            }),
        }
    }

    pub fn log_request(&self, entry: RequestLogEntry) {
        tracing::info!(
            target: "axiom.request_audit",
            request_id = %entry.id,
            model = %entry.model,
            provider = %entry.provider,
            status = ?entry.status,
            stream = entry.stream,
            e2ee_protocol = entry.e2ee.protocol.as_deref().unwrap_or("unavailable"),
            encryption_version = entry.e2ee.encryption_version.unwrap_or_default(),
            request_encrypted = entry.e2ee.request_encrypted,
            backend_key_accepted = entry.e2ee.backend_key_accepted,
            response_decrypted = entry.e2ee.response_decrypted,
            tee_verified = entry.tee.verified,
            prompt_tokens = entry.prompt_tokens,
            completion_tokens = entry.completion_tokens,
            duration_ms = entry.duration_ms,
            error_kind = entry.error_kind.as_deref().unwrap_or("none"),
            "proxy request audit completed"
        );
        let mut log = self.request_log.write().unwrap();
        if let Err(error) = log.push(entry) {
            tracing::warn!(
                target: "axiom.request_audit",
                error_kind = ?error.kind(),
                "request history metadata could not be persisted"
            );
        }
    }

    pub fn recent_requests(&self, limit: usize) -> Vec<RequestLogEntry> {
        let log = self.request_log.read().unwrap();
        log.recent(limit)
    }

    pub fn api_key(&self) -> Option<String> {
        self.api_key.read().unwrap().clone()
    }

    pub fn set_api_key(&self, key: Option<String>) {
        *self.api_key.write().unwrap() = key;
    }

    /// Fetch the model list from the relay and cache it. Called on startup and lazily.
    pub async fn refresh_models(&self) -> Result<Vec<RelayModel>> {
        let key = self
            .api_key()
            .ok_or_else(|| CoreError::Relay("no API key configured".into()))?;
        let advertised = self.relay.list_models(&key).await?;
        let mut models = Vec::with_capacity(advertised.len());
        for model in advertised {
            if !self.registry.contains(&model.provider) {
                tracing::warn!(
                    provider = %model.provider,
                    model = %model.id,
                    "model omitted because this proxy has no local provider engine"
                );
                continue;
            }
            self.registry.for_model(&model)?;
            models.push(model);
        }
        if models.is_empty() {
            return Err(CoreError::Provider(
                "backend advertised no models supported by this proxy".into(),
            ));
        }
        *self.models.write().unwrap() = models.clone();
        Ok(models)
    }

    fn cached_models(&self) -> Vec<RelayModel> {
        self.models.read().unwrap().clone()
    }

    /// Resolve a client-supplied model string against the catalog by id, full provider name, or
    /// base_url; returns the catalog entry. Refreshes the catalog once on a miss.
    pub async fn resolve_model(&self, requested: &str) -> Result<RelayModel> {
        if let Some(found) = Self::match_model(&self.cached_models(), requested)? {
            return Ok(found);
        }
        let models = self.refresh_models().await?;
        Self::match_model(&models, requested)?
            .ok_or_else(|| CoreError::Relay(format!("unknown model: {requested}")))
    }

    fn match_model(models: &[RelayModel], requested: &str) -> Result<Option<RelayModel>> {
        if let Some(model) = models.iter().find(|model| model.id == requested) {
            return Ok(Some(model.clone()));
        }
        let mut matches = models
            .iter()
            .filter(|model| model.model == requested || model.base_url == requested);
        let first = matches.next().cloned();
        if matches.next().is_some() {
            return Err(CoreError::Relay(format!(
                "ambiguous model reference: {requested}; use a provider offering id"
            )));
        }
        Ok(first)
    }

    /// Locally verify (and cache) the model TEE attestation. Single-flight per model; fail-closed.
    pub async fn ensure_verified(&self, model: &RelayModel) -> Result<Arc<VerifiedModel>> {
        Ok(self.ensure_verified_with_receipt(model).await?.verified)
    }

    pub async fn ensure_verified_with_receipt(
        &self,
        model: &RelayModel,
    ) -> Result<AttestationReceipt> {
        if let Some(entry) = self.attestations.read().unwrap().get(&model.id) {
            if self.cached_attestation_is_fresh(entry) {
                return Ok(AttestationReceipt {
                    verified: entry.verified.clone(),
                    verified_at_unix_ms: entry.verified_at_unix_ms,
                    age_ms: entry.at.elapsed().as_millis() as u64,
                });
            }
        }
        let lock = {
            let mut inflight = self.inflight.write().unwrap();
            inflight
                .entry(model.id.clone())
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone()
        };
        let _guard = lock.lock().await;
        // Re-check: another task may have verified while we waited.
        if let Some(entry) = self.attestations.read().unwrap().get(&model.id) {
            if self.cached_attestation_is_fresh(entry) {
                return Ok(AttestationReceipt {
                    verified: entry.verified.clone(),
                    verified_at_unix_ms: entry.verified_at_unix_ms,
                    age_ms: entry.at.elapsed().as_millis() as u64,
                });
            }
        }
        let engine = self.registry.for_model(model)?;
        let api_key = self
            .api_key()
            .ok_or_else(|| CoreError::Relay("no API key configured".into()))?;
        let verified = Arc::new(
            engine
                .attestor
                .verify_model(AttestationRequest {
                    base_url: &model.base_url,
                    model_id: &model.id,
                    expected_model: &model.model,
                    relay: self.relay.as_ref(),
                    api_key: &api_key,
                })
                .await?,
        );
        let verified_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.attestations.write().unwrap().insert(
            model.id.clone(),
            CachedAttestation {
                verified: verified.clone(),
                at: Instant::now(),
                verified_at_unix_ms,
            },
        );
        Ok(AttestationReceipt {
            verified,
            verified_at_unix_ms,
            age_ms: 0,
        })
    }

    /// Test helper: pre-seed the model catalog and a fresh attestation entry so handler tests can
    /// skip the network. No-op-safe in production but only called from tests.
    #[doc(hidden)]
    pub fn seed_for_test(&self, model: RelayModel, model_public_key_hex: String) {
        let id = model.id.clone();
        self.models.write().unwrap().push(model);
        self.attestations.write().unwrap().insert(
            id,
            CachedAttestation {
                verified: Arc::new(VerifiedModel {
                    model_public_key_hex,
                    tls_fingerprint: Some("56".repeat(32)),
                    checks: axiom_core::attestation::near_checks("UpToDate", "verified"),
                    provider_state: None,
                    expires_at_unix: None,
                }),
                at: Instant::now(),
                verified_at_unix_ms: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            },
        );
    }

    /// Snapshot of cached, still-fresh attestations for the trust panel.
    pub fn cached_attestations(&self) -> Vec<(String, Arc<VerifiedModel>)> {
        self.attestations
            .read()
            .unwrap()
            .iter()
            .filter(|(_, e)| self.cached_attestation_is_fresh(e))
            .map(|(id, e)| (id.clone(), e.verified.clone()))
            .collect()
    }

    /// Drop a cached attestation so the next request (or a manual re-verify) re-attests.
    pub fn invalidate_attestation(&self, model_id: &str) {
        self.attestations.write().unwrap().remove(model_id);
    }

    /// base_url for a catalog model id, if known.
    pub fn model_base_url(&self, model_id: &str) -> Option<String> {
        self.model_info(model_id).map(|m| m.base_url)
    }

    /// Full catalog entry for a model id, if known.
    pub fn model_info(&self, model_id: &str) -> Option<RelayModel> {
        self.models
            .read()
            .unwrap()
            .iter()
            .find(|m| m.id == model_id)
            .cloned()
    }

    pub fn record_start(&self) {
        self.counters.total_requests.fetch_add(1, Ordering::Relaxed);
        self.counters
            .active_requests
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_finish(&self, prompt: u32, completion: u32) {
        self.counters
            .active_requests
            .fetch_sub(1, Ordering::Relaxed);
        self.counters
            .prompt_tokens
            .fetch_add(prompt as u64, Ordering::Relaxed);
        self.counters
            .completion_tokens
            .fetch_add(completion as u64, Ordering::Relaxed);
    }
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model(id: &str, provider: &str, upstream: &str, base_url: &str) -> RelayModel {
        RelayModel {
            id: id.into(),
            label: id.into(),
            short_label: id.into(),
            model: upstream.into(),
            base_url: base_url.into(),
            provider: provider.into(),
            provider_label: provider.into(),
            e2ee_protocol: "test-e2ee-v1".into(),
            e2ee_encryption_version: 1,
            attestation_protocol: "test-attestation-v1".into(),
            context_window_tokens: 4096,
            max_output_tokens: 1024,
            supported_reasoning_efforts: Vec::new(),
        }
    }

    #[test]
    fn offering_id_disambiguates_same_model_from_multiple_providers() {
        let models = vec![
            model(
                "shared-provider-a",
                "provider-a",
                "org/shared-model",
                "https://a.example/v1",
            ),
            model(
                "shared-provider-b",
                "provider-b",
                "org/shared-model",
                "https://b.example/v1",
            ),
        ];

        assert_eq!(
            ProxyCore::match_model(&models, "shared-provider-b")
                .unwrap()
                .unwrap()
                .provider,
            "provider-b"
        );
        assert!(ProxyCore::match_model(&models, "org/shared-model").is_err());
    }
}
