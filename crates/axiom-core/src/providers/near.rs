//! NEAR AI provider engine: `near-v2` E2EE (see [`crate::e2ee`]) over the NEAR gateway
//! attestation format (see [`crate::attestation`]).

use async_trait::async_trait;

use crate::attestation;
use crate::e2ee::{decode_public_key_hex, encrypt_to_model, ClientKeypair};
use crate::error::Result;
use crate::provider::{AttestationRequest, Attestor, CipherSession, ProviderCipher, VerifiedModel};

/// Matches the backend's usage/catalog provider id.
pub const NEAR_PROVIDER_ID: &str = "near";
pub const NEAR_ATTESTATION_PROTOCOL: &str = "near-tdx-nvidia-v1";
pub const NEAR_V2_PROTOCOL: &str = "near-v2";
pub const NEAR_V2_ENCRYPTION_VERSION: u8 = 2;

/// NEAR's multi-model gateway needs an explicit model selector on attestation requests;
/// per-model hosts (`*.completions.near.ai`) do not.
pub fn is_near_gateway(base_url: &str) -> bool {
    base_url.contains("cloud-api.near.ai")
}

pub struct NearAttestor;

#[async_trait]
impl Attestor for NearAttestor {
    fn protocol(&self) -> &'static str {
        NEAR_ATTESTATION_PROTOCOL
    }

    async fn verify_model(&self, request: AttestationRequest<'_>) -> Result<VerifiedModel> {
        attestation::verify_model(request.base_url, request.expected_model).await
    }
}

pub struct NearCipher;

impl ProviderCipher for NearCipher {
    fn protocol(&self) -> &'static str {
        NEAR_V2_PROTOCOL
    }

    fn encryption_version(&self) -> u8 {
        NEAR_V2_ENCRYPTION_VERSION
    }

    fn new_session(&self, verified: &VerifiedModel) -> Result<Box<dyn CipherSession>> {
        let model_pub = decode_public_key_hex(&verified.model_public_key_hex)?;
        Ok(Box::new(NearSession {
            keypair: ClientKeypair::generate(),
            model_pub,
        }))
    }
}

/// A fresh ed25519 identity per request so the provider cannot link requests; never persisted.
struct NearSession {
    keypair: ClientKeypair,
    model_pub: [u8; 32],
}

impl CipherSession for NearSession {
    fn client_public_key_hex(&self) -> Option<String> {
        Some(self.keypair.public_hex.clone())
    }

    fn is_ready(&self) -> bool {
        !self.keypair.public_hex.is_empty()
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Result<String> {
        encrypt_to_model(&self.model_pub, plaintext)
    }

    fn decrypt(&mut self, wire: &str) -> Result<Vec<u8>> {
        self.keypair.decrypt(wire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn near_session_roundtrip() {
        let cipher = NearCipher;
        assert_eq!(cipher.protocol(), "near-v2");
        assert_eq!(cipher.encryption_version(), 2);
        // Encrypt to the session's own client key so we can decrypt without a model secret.
        let probe = ClientKeypair::generate();
        let mut session = cipher
            .new_session(&VerifiedModel {
                model_public_key_hex: probe.public_hex.clone(),
                tls_fingerprint: None,
                checks: vec![],
                provider_state: None,
                expires_at_unix: None,
            })
            .unwrap();
        assert!(session.client_public_key_hex().is_some());
        let wire = session.encrypt(b"hello provider").unwrap();
        assert_eq!(probe.decrypt(&wire).unwrap(), b"hello provider");
    }

    #[test]
    fn gateway_detection() {
        assert!(is_near_gateway("https://cloud-api.near.ai/v1"));
        assert!(!is_near_gateway(
            "https://gemma-4-31b.completions.near.ai/v1"
        ));
    }
}
