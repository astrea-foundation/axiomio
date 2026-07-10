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
use crate::relay::RelayModel;

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
}

/// Verifies one model's TEE attestation on this machine. Fail-closed: an Err means the model
/// must not receive ciphertext.
#[async_trait]
pub trait Attestor: Send + Sync {
    async fn verify_model(&self, base_url: &str, expected_model: &str) -> Result<VerifiedModel>;
}

/// One request's client-side crypto state. `&mut self` so stateful protocols (e.g. ordered-stream
/// constructions) fit without interior mutability.
pub trait CipherSession: Send {
    /// Public key the relay forwards to the provider, when the protocol has one.
    fn client_public_key_hex(&self) -> Option<String>;
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<String>;
    fn decrypt(&mut self, wire: &str) -> Result<Vec<u8>>;
}

/// Factory for per-request cipher sessions, parameterized by the attested model key material.
pub trait ProviderCipher: Send + Sync {
    fn protocol(&self) -> &'static str;
    fn encryption_version(&self) -> u8;
    fn new_session(&self, model_key_material: &str) -> Result<Box<dyn CipherSession>>;
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
        let mut engines = HashMap::new();
        engines.insert(
            NEAR_PROVIDER_ID,
            ProviderEngine {
                id: NEAR_PROVIDER_ID,
                attestor: Arc::new(NearAttestor),
                cipher: Arc::new(NearCipher),
            },
        );
        Self { engines }
    }

    pub fn get(&self, provider_id: &str) -> Result<&ProviderEngine> {
        self.engines
            .get(provider_id)
            .ok_or_else(|| CoreError::Provider(format!("unknown provider: {provider_id}")))
    }

    pub fn for_model(&self, model: &RelayModel) -> Result<&ProviderEngine> {
        self.get(&model.provider)
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::builtin()
    }
}
