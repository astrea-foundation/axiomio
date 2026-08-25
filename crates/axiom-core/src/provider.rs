//! Provider abstraction: each upstream E2EE TEE provider supplies an [`Attestor`] (verify a
//! model's TEE and return its key material) and a [`ProviderCipher`] (per-request client-side
//! crypto). A static [`ProviderRegistry`] maps `RelayModel.provider` ids to engines; adding a
//! provider means one module under `providers/` plus one registry entry.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};
use crate::providers::near::{NearAttestor, NearCipher, NEAR_PROVIDER_ID};
use crate::providers::phala::{PhalaAttestor, PhalaCipher, PHALA_PROVIDER_ID};
use crate::relay::{RelayApi, RelayCompletion, RelayModel};

/// One named attestation check for display purposes. A model is only usable when the attestor
/// returned Ok — checks exist so the UI renders provider-appropriate proof rows instead of
/// hardcoding Intel/NVIDIA.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct VerificationCheck {
    pub id: String,
    pub label: String,
    pub status: String,
    pub ok: bool,
}

impl VerificationCheck {
    pub fn new(id: &str, label: &str, status: impl Into<String>, ok: bool) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            status: status.into(),
            ok,
        }
    }
}

/// Result of a full, successful verification: the provider's model key material plus the ordered
/// checks that passed.
#[derive(Debug, Clone)]
pub struct VerifiedModel {
    pub model_public_key_hex: String,
    pub tls_fingerprint: Option<String>,
    pub checks: Vec<VerificationCheck>,
    /// Provider-specific, locally verified public state (never prompt or key material). Phala
    /// uses this for the nonce-bound keyset, receipt keys, and content-addressed worker sessions.
    pub provider_state: Option<serde_json::Value>,
    /// Hard expiry imposed by the provider's verified evidence. The cache must never outlive it.
    pub expires_at_unix: Option<u64>,
}

/// Everything an attestor needs to challenge evidence through the authenticated Axiom relay.
/// NEAR obtains evidence directly from its model endpoint; Phala deliberately uses the relay so
/// the local client never needs the provider API credential.
pub struct AttestationRequest<'a> {
    pub base_url: &'a str,
    pub model_id: &'a str,
    pub expected_model: &'a str,
    pub relay: &'a dyn RelayApi,
    pub api_key: &'a str,
}

/// Verifies one model's TEE attestation on this machine. Fail-closed: an Err means the model
/// must not receive ciphertext.
#[async_trait]
pub trait Attestor: Send + Sync {
    /// Stable identifier for the provider-specific evidence format and verification procedure.
    fn protocol(&self) -> &'static str;
    async fn verify_model(&self, request: AttestationRequest<'_>) -> Result<VerifiedModel>;
}

/// Plaintext metadata used only inside the local process to calculate a provider receipt hash.
/// It is never serialized into a relay request. Protocols that do not require this binding ignore
/// it. Phala rejects extended/tool fields until their ACI v2 AAD contract is implemented.
#[derive(Debug, Clone)]
pub struct PlainProviderMessage {
    pub role: String,
    pub content: Option<String>,
    pub assistant_null_content: bool,
    pub has_extended_fields: bool,
}

#[derive(Debug, Clone)]
pub struct PlainProviderRequest {
    pub model: String,
    pub messages: Vec<PlainProviderMessage>,
    pub max_tokens: u32,
    pub sampling: Option<serde_json::Value>,
    pub response_format: Option<serde_json::Value>,
    pub reasoning_effort: Option<String>,
    pub has_tools: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DecryptedProviderCompletion {
    pub content: Option<String>,
    pub reasoning_content: Option<String>,
    pub refusal: Option<String>,
}

/// One request's client-side crypto state. `&mut self` so stateful protocols (e.g. ordered-stream
/// constructions) fit without interior mutability.
pub trait CipherSession: Send {
    /// Public key the relay forwards to the provider, when the protocol has one.
    fn client_public_key_hex(&self) -> Option<String>;
    /// Provider-specific session setup was completed and the session is safe to use.
    fn is_ready(&self) -> bool;
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<String>;
    fn decrypt(&mut self, wire: &str) -> Result<Vec<u8>>;

    fn supports_streaming(&self) -> bool {
        true
    }

    fn encrypt_field(&mut self, plaintext: &[u8], _field: &str) -> Result<String> {
        self.encrypt(plaintext)
    }

    /// Build the provider-specific context sent beside ciphertext. The returned value may contain
    /// only non-secret proof/binding metadata.
    fn prepare_request_context(
        &mut self,
        _request: &PlainProviderRequest,
    ) -> Result<Option<serde_json::Value>> {
        Ok(None)
    }

    /// Provider-specific receipt-gated completion path. `None` means the caller should use the
    /// ordinary per-field decrypt methods (currently NEAR). Phala returns plaintext only after
    /// its complete receipt chain verifies.
    fn decrypt_verified_completion(
        &mut self,
        _completion: &RelayCompletion,
    ) -> Result<Option<DecryptedProviderCompletion>> {
        Ok(None)
    }
}

/// Factory for per-request cipher sessions, parameterized by the attested model key material.
pub trait ProviderCipher: Send + Sync {
    fn protocol(&self) -> &'static str;
    fn encryption_version(&self) -> u8;
    fn new_session(&self, verified: &VerifiedModel) -> Result<Box<dyn CipherSession>>;
}

pub struct ProviderEngine {
    pub id: &'static str,
    pub attestor: Arc<dyn Attestor>,
    pub cipher: Arc<dyn ProviderCipher>,
}

pub struct ProviderRegistry {
    engines: HashMap<&'static str, ProviderEngine>,
}

impl ProviderRegistry {
    /// The static set of built-in providers.
    pub fn builtin() -> Self {
        Self::new(vec![
            ProviderEngine {
                id: NEAR_PROVIDER_ID,
                attestor: Arc::new(NearAttestor),
                cipher: Arc::new(NearCipher),
            },
            ProviderEngine {
                id: PHALA_PROVIDER_ID,
                attestor: Arc::new(PhalaAttestor),
                cipher: Arc::new(PhalaCipher),
            },
        ])
        .expect("built-in provider ids must be unique")
    }

    pub fn new(engines: Vec<ProviderEngine>) -> Result<Self> {
        let mut by_id = HashMap::new();
        for engine in engines {
            if by_id.insert(engine.id, engine).is_some() {
                return Err(CoreError::Provider("duplicate provider id".into()));
            }
        }
        Ok(Self { engines: by_id })
    }

    pub fn get(&self, provider_id: &str) -> Result<&ProviderEngine> {
        self.engines
            .get(provider_id)
            .ok_or_else(|| CoreError::Provider(format!("unknown provider: {provider_id}")))
    }

    pub fn contains(&self, provider_id: &str) -> bool {
        self.engines.contains_key(provider_id)
    }

    pub fn for_model(&self, model: &RelayModel) -> Result<&ProviderEngine> {
        let engine = self.get(&model.provider)?;
        if model.e2ee_protocol != engine.cipher.protocol()
            || model.e2ee_encryption_version != engine.cipher.encryption_version()
            || model.attestation_protocol != engine.attestor.protocol()
        {
            return Err(CoreError::Provider(format!(
                "provider contract mismatch for model {}",
                model.id
            )));
        }
        Ok(engine)
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::builtin()
    }
}
