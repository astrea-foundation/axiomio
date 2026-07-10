//! Client-side E2EE, a faithful port of `backend/src/axiom_api/inference/e2ee.py`.
//!
//! Protocol (`near-v2`): the client holds an ed25519 keypair and publishes the ed25519 public key
//! as `X-Client-Pub-Key`. To encrypt to the model, its ed25519 public key is converted to x25519,
//! an ephemeral x25519 key does ECDH, HKDF-SHA256 (salt=None, info=`ed25519_encryption`) derives a
//! 32-byte key, and XChaCha20-Poly1305-IETF (random 24-byte nonce, no AAD) seals the plaintext.
//! Wire = `ephemeral_pub(32) || nonce(24) || ciphertext+tag`, lowercase hex.
//!
//! Every byte here is pinned against the Python implementation by
//! `fixtures/e2ee_vectors/near-v2.json` (one vector file per E2EE protocol).

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{CoreError, Result};

const HKDF_INFO: &[u8] = b"ed25519_encryption";
const WIRE_PREFIX_LEN: usize = 32 + 24; // ephemeral pub + XChaCha nonce

/// Strip an optional `0x`, lowercase, and decode a 32-byte public key.
pub fn decode_public_key_hex(value: &str) -> Result<[u8; 32]> {
    let stripped = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    if stripped.len() != 64 {
        return Err(CoreError::Key(
            "public key must be 32 bytes (64 hex chars)".into(),
        ));
    }
    let bytes = hex::decode(stripped).map_err(|e| CoreError::Hex(e.to_string()))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// ed25519 public key -> x25519 public key (Edwards -> Montgomery),
/// matching libsodium `crypto_sign_ed25519_pk_to_curve25519`.
pub fn ed25519_public_to_x25519(ed_pub: &[u8; 32]) -> Result<[u8; 32]> {
    let compressed = CompressedEdwardsY(*ed_pub);
    let point = compressed
        .decompress()
        .ok_or_else(|| CoreError::Key("invalid ed25519 public key point".into()))?;
    Ok(point.to_montgomery().to_bytes())
}

/// ed25519 secret (seed||public, 64 bytes) -> x25519 secret, matching libsodium
/// `crypto_sign_ed25519_sk_to_curve25519`: clamp(SHA-512(seed)[0..32]).
pub fn ed25519_secret_to_x25519_secret(secret_64: &[u8]) -> Result<[u8; 32]> {
    if secret_64.len() != 64 {
        return Err(CoreError::Key(
            "ed25519 secret must be 64 bytes (seed||public)".into(),
        ));
    }
    let hash = Sha512::digest(&secret_64[0..32]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&hash[0..32]);
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
    Ok(s)
}

fn derive_key(shared_secret: &[u8]) -> [u8; 32] {
    // salt=None matches Python `HKDF(..., salt=None)` == HKDF with an all-zero salt block.
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key)
        .expect("32 is a valid HKDF-SHA256 length");
    key
}

/// Encrypt plaintext to a model whose ed25519 public key is `model_ed25519_pub`. Returns the
/// lowercase-hex wire payload.
pub fn encrypt_to_model(model_ed25519_pub: &[u8; 32], plaintext: &[u8]) -> Result<String> {
    let recipient_x = ed25519_public_to_x25519(model_ed25519_pub)?;
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let ephemeral_pub = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&PublicKey::from(recipient_x));
    let key = derive_key(shared.as_bytes());

    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| CoreError::Decrypt)?;

    let mut wire = Vec::with_capacity(WIRE_PREFIX_LEN + ciphertext.len());
    wire.extend_from_slice(ephemeral_pub.as_bytes());
    wire.extend_from_slice(&nonce_bytes);
    wire.extend_from_slice(&ciphertext);
    Ok(hex::encode(wire))
}

/// Decrypt a wire payload (hex) using the recipient's x25519 secret.
pub fn decrypt_wire(recipient_x25519_secret: &[u8; 32], wire_hex: &str) -> Result<Vec<u8>> {
    let stripped = wire_hex
        .trim()
        .strip_prefix("0x")
        .unwrap_or(wire_hex.trim());
    let wire = hex::decode(stripped).map_err(|e| CoreError::Hex(e.to_string()))?;
    if wire.len() <= WIRE_PREFIX_LEN {
        return Err(CoreError::CiphertextTooShort);
    }
    let mut eph = [0u8; 32];
    eph.copy_from_slice(&wire[0..32]);
    let nonce = &wire[32..WIRE_PREFIX_LEN];
    let ciphertext = &wire[WIRE_PREFIX_LEN..];

    let secret = StaticSecret::from(*recipient_x25519_secret);
    let shared = secret.diffie_hellman(&PublicKey::from(eph));
    let key = derive_key(shared.as_bytes());
    let cipher = XChaCha20Poly1305::new((&key).into());
    cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| CoreError::Decrypt)
}

/// A fresh ed25519 client identity for one relay request. The proxy generates one per request so
/// the provider cannot link requests, and never persists it.
pub struct ClientKeypair {
    pub public_hex: String,
    pub x25519_secret: [u8; 32],
}

impl ClientKeypair {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let signing = SigningKey::from_bytes(&seed);
        let public = signing.verifying_key();
        let mut secret_64 = [0u8; 64];
        secret_64[0..32].copy_from_slice(&signing.to_bytes());
        secret_64[32..64].copy_from_slice(public.as_bytes());
        let x25519_secret = ed25519_secret_to_x25519_secret(&secret_64)
            .expect("64-byte secret is valid by construction");
        Self {
            public_hex: hex::encode(public.as_bytes()),
            x25519_secret,
        }
    }

    /// Decrypt a wire payload addressed to this client.
    pub fn decrypt(&self, wire_hex: &str) -> Result<Vec<u8>> {
        decrypt_wire(&self.x25519_secret, wire_hex)
    }
}

/// TDX `report_data` binding check, matching `verify_report_data` in near_verifier.py:
/// `report_data[0:32] == sha256(raw_key || raw_fp)` and `report_data[32:64] == nonce`.
/// All inputs are hex; the hashed material is the RAW decoded bytes, not the hex strings.
pub fn verify_report_data(
    report_data_hex: &str,
    signing_key_hex: &str,
    tls_fingerprint_hex: &str,
    nonce_hex: &str,
) -> Result<bool> {
    let decode = |s: &str| hex::decode(s).map_err(|e| CoreError::Hex(e.to_string()));
    let report_data = decode(report_data_hex)?;
    if report_data.len() < 64 {
        return Ok(false);
    }
    let key = decode(signing_key_hex)?;
    let fp = decode(tls_fingerprint_hex)?;
    let nonce = decode(nonce_hex)?;

    let mut hasher = Sha256::new();
    hasher.update(&key);
    hasher.update(&fp);
    let expected = hasher.finalize();
    Ok(report_data[0..32] == expected[..] && report_data[32..64] == nonce[..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn vectors() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/e2ee_vectors/near-v2.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).expect("fixtures present")).unwrap()
    }

    fn hex32(s: &str) -> [u8; 32] {
        let b = hex::decode(s).unwrap();
        let mut out = [0u8; 32];
        out.copy_from_slice(&b);
        out
    }

    #[test]
    fn public_key_conversion_matches_python() {
        for v in vectors()["key_conversions"].as_array().unwrap() {
            let ed = hex32(v["ed25519_public_hex"].as_str().unwrap());
            let got = hex::encode(ed25519_public_to_x25519(&ed).unwrap());
            assert_eq!(got, v["x25519_public_hex"].as_str().unwrap());
        }
    }

    #[test]
    fn secret_key_conversion_matches_python() {
        for v in vectors()["secret_conversions"].as_array().unwrap() {
            let sk = hex::decode(v["ed25519_secret_hex"].as_str().unwrap()).unwrap();
            let got = hex::encode(ed25519_secret_to_x25519_secret(&sk).unwrap());
            assert_eq!(got, v["x25519_secret_hex"].as_str().unwrap());
        }
    }

    #[test]
    fn hkdf_matches_python() {
        for v in vectors()["hkdf_vectors"].as_array().unwrap() {
            let shared = hex::decode(v["shared_secret_hex"].as_str().unwrap()).unwrap();
            let got = hex::encode(derive_key(&shared));
            assert_eq!(got, v["derived_key_hex"].as_str().unwrap());
        }
    }

    #[test]
    fn decrypts_python_ciphertext() {
        for v in vectors()["encrypt_roundtrips"].as_array().unwrap() {
            let secret = hex32(v["recipient_x25519_secret_hex"].as_str().unwrap());
            let plaintext = decrypt_wire(&secret, v["wire_hex"].as_str().unwrap()).unwrap();
            assert_eq!(
                String::from_utf8(plaintext).unwrap(),
                v["expected_plaintext"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn rust_encrypt_python_decryptable_roundtrip() {
        // Rust encrypts to the model pubkey; the model's x25519 secret (from fixtures) decrypts.
        let v = &vectors()["encrypt_roundtrips"][0];
        let model_pub = hex32(v["recipient_ed25519_public_hex"].as_str().unwrap());
        let secret = hex32(v["recipient_x25519_secret_hex"].as_str().unwrap());
        let wire = encrypt_to_model(&model_pub, b"round trip through rust").unwrap();
        let back = decrypt_wire(&secret, &wire).unwrap();
        assert_eq!(back, b"round trip through rust");
    }

    #[test]
    fn client_keypair_self_roundtrip() {
        let client = ClientKeypair::generate();
        let ed_pub = hex32(&client.public_hex);
        let wire = encrypt_to_model(&ed_pub, b"hello self").unwrap();
        assert_eq!(client.decrypt(&wire).unwrap(), b"hello self");
    }

    #[test]
    fn report_data_binding_matches_python() {
        for v in vectors()["report_data_vectors"].as_array().unwrap() {
            let ok = verify_report_data(
                v["report_data_hex"].as_str().unwrap(),
                v["signing_key_hex"].as_str().unwrap(),
                v["tls_fingerprint_hex"].as_str().unwrap(),
                v["nonce_hex"].as_str().unwrap(),
            )
            .unwrap();
            assert_eq!(ok, v["valid"].as_bool().unwrap());
        }
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let v = &vectors()["encrypt_roundtrips"][0];
        let secret = hex32(v["recipient_x25519_secret_hex"].as_str().unwrap());
        let mut wire = v["wire_hex"].as_str().unwrap().to_string();
        // flip the last hex nibble of the tag
        wire.pop();
        wire.push(if v["wire_hex"].as_str().unwrap().ends_with('0') {
            '1'
        } else {
            '0'
        });
        assert!(decrypt_wire(&secret, &wire).is_err());
    }
}
