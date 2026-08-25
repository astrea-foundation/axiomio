//! Phala ACI v2 provider engine. The local client verifies the nonce-bound gateway TDX quote,
//! measured gateway source, X25519/Ed25519 keyset, and content-addressed worker sessions before it
//! encrypts. It decrypts a completion only after the gateway's signed receipt binds the exact
//! plaintext request hash, exact encrypted response bytes, requested model, and cited worker.

use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use async_trait::async_trait;
use base64::Engine;
use dcap_qvl::{verify::rustcrypto, QuoteCollateralV3};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256, Sha384};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::attestation::now_unix;
use crate::error::{CoreError, Result};
use crate::provider::{
    AttestationRequest, Attestor, CipherSession, DecryptedProviderCompletion, PlainProviderRequest,
    ProviderCipher, VerificationCheck, VerifiedModel,
};
use crate::relay::RelayCompletion;

pub const PHALA_PROVIDER_ID: &str = "phala";
pub const PHALA_ATTESTATION_PROTOCOL: &str = "phala-aci-tdx-v1";
pub const PHALA_ACI_V2_PROTOCOL: &str = "phala-aci-v2";
pub const PHALA_ACI_V2_ENCRYPTION_VERSION: u8 = 2;

const E2EE_ALGORITHM: &str = "x25519-aes-256-gcm-hkdf-sha256";
const E2EE_KEY_ID: &str = "dstack-kms-e2ee-x25519-v1";
const HKDF_INFO: &[u8] = b"aci.e2ee.v2.x25519";
const APPROVED_GATEWAY_COMMIT: &str = "b6b5c1b82f6fc59490db5a5255bf4493805e66c6";
const APPROVED_REPOSITORIES: &[&str] = &[
    "https://github.com/Dstack-TEE/private-ai-gateway",
    "https://github.com/Dstack-TEE/private-ai-gateway.git",
];

#[derive(Debug, Deserialize)]
struct CollateralWire {
    pck_crl_issuer_chain: String,
    root_ca_crl: String,
    pck_crl: String,
    tcb_info_issuer_chain: String,
    tcb_info: String,
    tcb_info_signature: String,
    qe_identity_issuer_chain: String,
    qe_identity: String,
    qe_identity_signature: String,
    pck_certificate_chain: Option<String>,
}

impl CollateralWire {
    fn into_qvl(self) -> Result<QuoteCollateralV3> {
        Ok(QuoteCollateralV3 {
            pck_crl_issuer_chain: self.pck_crl_issuer_chain,
            root_ca_crl: decode_hex("root_ca_crl", &self.root_ca_crl)?,
            pck_crl: decode_hex("pck_crl", &self.pck_crl)?,
            tcb_info_issuer_chain: self.tcb_info_issuer_chain,
            tcb_info: self.tcb_info,
            tcb_info_signature: decode_hex("tcb_info_signature", &self.tcb_info_signature)?,
            qe_identity_issuer_chain: self.qe_identity_issuer_chain,
            qe_identity: self.qe_identity,
            qe_identity_signature: decode_hex(
                "qe_identity_signature",
                &self.qe_identity_signature,
            )?,
            pck_certificate_chain: self.pck_certificate_chain,
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PhalaWorkerSession {
    session_id: String,
    established_at: u64,
    expires_at: u64,
    record: Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PhalaAttestationState {
    model: String,
    keyset_digest: String,
    gateway_public_key_hex: String,
    receipt_public_keys: BTreeMap<String, String>,
    worker_sessions: BTreeMap<String, PhalaWorkerSession>,
}

fn attestation(message: impl Into<String>) -> CoreError {
    CoreError::Attestation(message.into())
}

fn provider(message: impl Into<String>) -> CoreError {
    CoreError::Provider(message.into())
}

fn object<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| attestation(format!("Phala {label} is not an object")))
}

fn required_str<'a>(object: &'a Map<String, Value>, key: &str, label: &str) -> Result<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| attestation(format!("Phala {label} is missing")))
}

fn decode_hex(label: &str, value: &str) -> Result<Vec<u8>> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|error| attestation(format!("Phala {label} must be hex: {error}")))
}

fn decode_32(label: &str, value: &str) -> Result<[u8; 32]> {
    decode_hex(label, value)?
        .try_into()
        .map_err(|_| attestation(format!("Phala {label} must be exactly 32 bytes")))
}

fn sorted_json(value: &Value) -> Result<Value> {
    match value {
        Value::Array(values) => values
            .iter()
            .map(sorted_json)
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        Value::Object(values) => {
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            let mut output = Map::new();
            for key in keys {
                output.insert(key.clone(), sorted_json(&values[key])?);
            }
            Ok(Value::Object(output))
        }
        Value::Number(number) => {
            if number.as_i64().is_none() && number.as_u64().is_none() {
                return Err(attestation(
                    "Phala canonical JSON accepts only integer numbers",
                ));
            }
            Ok(value.clone())
        }
        _ => Ok(value.clone()),
    }
}

fn canonical_json(value: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(&sorted_json(value)?)
        .map_err(|error| attestation(format!("Phala canonical JSON failed: {error}")))
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn random_nonce_hex() -> String {
    let mut nonce = [0_u8; 32];
    OsRng.fill_bytes(&mut nonce);
    hex::encode(nonce)
}

fn asserted(record: &Map<String, Value>, claim: &str) -> bool {
    record
        .get("claims")
        .and_then(Value::as_object)
        .and_then(|claims| claims.get(claim))
        .and_then(Value::as_object)
        .and_then(|claim| claim.get("status"))
        .and_then(Value::as_str)
        .is_some_and(|status| status.eq_ignore_ascii_case("asserted"))
}

fn replay_rtmr3(event_log: &str) -> Result<([u8; 48], String)> {
    let events: Value = serde_json::from_str(event_log)
        .map_err(|error| attestation(format!("Phala gateway event log is invalid: {error}")))?;
    let events = events
        .as_array()
        .ok_or_else(|| attestation("Phala gateway event log is not an array"))?;
    let mut current = [0_u8; 48];
    let mut compose_hashes = Vec::new();
    let mut system_ready = false;
    for (index, event) in events.iter().enumerate() {
        let event = object(event, &format!("gateway event {index}"))?;
        if event.get("imr").and_then(Value::as_u64) != Some(3) {
            continue;
        }
        let digest = decode_hex(
            &format!("gateway event {index} digest"),
            required_str(event, "digest", "gateway event digest")?,
        )?;
        if digest.len() > 48 {
            return Err(attestation("Phala gateway event digest is too long"));
        }
        let mut padded = [0_u8; 48];
        padded[..digest.len()].copy_from_slice(&digest);
        current = Sha384::digest([current.as_slice(), padded.as_slice()].concat()).into();
        match event.get("event").and_then(Value::as_str) {
            Some("system-ready") => system_ready = true,
            Some("compose-hash") if !system_ready => compose_hashes.push(
                event
                    .get("event_payload")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_lowercase(),
            ),
            _ => {}
        }
    }
    if compose_hashes.len() != 1 {
        return Err(attestation(
            "Phala gateway event log has no unique compose measurement",
        ));
    }
    Ok((current, compose_hashes.remove(0)))
}

fn verify_worker_session(value: &Value, minimum_ttl: u64) -> Result<PhalaWorkerSession> {
    let mut record = object(value, "worker session")?.clone();
    let session_id = required_str(&record, "session_id", "worker session id")?.to_lowercase();
    if session_id.len() != 64 || hex::decode(&session_id).is_err() {
        return Err(attestation("Phala worker session id is invalid"));
    }
    record.remove("session_id");
    if record.get("api_version").and_then(Value::as_str) != Some("aci/1") {
        return Err(attestation("Phala worker session is not aci/1"));
    }
    let record_value = Value::Object(record.clone());
    if hex::encode(Sha256::digest(canonical_json(&record_value)?)) != session_id {
        return Err(attestation("Phala worker session is not content addressed"));
    }
    let established_at = record
        .get("established_at")
        .and_then(Value::as_u64)
        .ok_or_else(|| attestation("Phala worker session has no establishment time"))?;
    let expires_at = record
        .get("expires_at")
        .and_then(Value::as_u64)
        .ok_or_else(|| attestation("Phala worker session has no expiry"))?;
    if expires_at <= now_unix().saturating_add(minimum_ttl) {
        return Err(attestation(
            "Phala worker session is expired or too close to expiry",
        ));
    }
    for claim in ["tee_attested", "tcb_up_to_date", "gpu_attested"] {
        if !asserted(&record, claim) {
            return Err(attestation(format!("Phala worker does not assert {claim}")));
        }
    }
    let bindings = record
        .get("channel_binding")
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty())
        .ok_or_else(|| attestation("Phala worker session has no channel binding"))?;
    for binding in bindings {
        let binding = object(binding, "worker channel binding")?;
        if !matches!(
            binding.get("type").and_then(Value::as_str),
            Some("tls_spki_sha256" | "e2ee_public_key_sha256")
        ) {
            return Err(attestation(
                "Phala worker session has an unsupported channel binding",
            ));
        }
    }
    let evidence = record
        .get("evidence")
        .and_then(Value::as_object)
        .ok_or_else(|| attestation("Phala worker session has no evidence object"))?;
    if !evidence.is_empty() {
        let data_uri = required_str(evidence, "data", "worker evidence data")?;
        let encoded = data_uri
            .split_once(";base64,")
            .map(|(_, encoded)| encoded)
            .ok_or_else(|| attestation("Phala worker evidence is not base64"))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|error| attestation(format!("Phala worker evidence is invalid: {error}")))?;
        let evidence_digest = sha256_digest(&bytes);
        if evidence.get("digest").and_then(Value::as_str) != Some(evidence_digest.as_str()) {
            return Err(attestation("Phala worker evidence digest mismatch"));
        }
    }
    Ok(PhalaWorkerSession {
        session_id,
        established_at,
        expires_at,
        record: record_value,
    })
}

pub struct PhalaAttestor;

#[async_trait]
impl Attestor for PhalaAttestor {
    fn protocol(&self) -> &'static str {
        PHALA_ATTESTATION_PROTOCOL
    }

    async fn verify_model(&self, request: AttestationRequest<'_>) -> Result<VerifiedModel> {
        let nonce = random_nonce_hex();
        let (key, evidence) = tokio::try_join!(
            request
                .relay
                .provider_e2ee_key(request.api_key, request.model_id),
            request
                .relay
                .provider_attestation_report(request.api_key, request.model_id, &nonce,)
        )?;
        if !key.verified
            || key.provider != PHALA_PROVIDER_ID
            || key.attestation_protocol != PHALA_ATTESTATION_PROTOCOL
            || key.e2ee_protocol != PHALA_ACI_V2_PROTOCOL
            || key.encryption_version != PHALA_ACI_V2_ENCRYPTION_VERSION
            || key.signing_algo != "x25519"
            || key.model_id != request.model_id
            || key.model != request.expected_model
            || key.base_url.trim_end_matches('/') != request.base_url.trim_end_matches('/')
        {
            return Err(attestation("Phala E2EE key identity mismatch"));
        }
        if evidence.provider != PHALA_PROVIDER_ID
            || evidence.attestation_protocol != PHALA_ATTESTATION_PROTOCOL
        {
            return Err(attestation("Phala attestation identity mismatch"));
        }
        let bundle = object(&evidence.evidence, "evidence bundle")?;
        let report = object(
            bundle
                .get("gateway_report")
                .ok_or_else(|| attestation("Phala gateway report is missing"))?,
            "gateway report",
        )?;
        if report.get("api_version").and_then(Value::as_str) != Some("aci/1") {
            return Err(attestation("Phala gateway is not aci/1"));
        }
        let capabilities = report
            .get("service_capabilities")
            .and_then(Value::as_object)
            .ok_or_else(|| attestation("Phala gateway capabilities are missing"))?;
        if capabilities.get("serving").and_then(Value::as_str) != Some("aggregator")
            || !capabilities
                .get("supported_e2ee_versions")
                .and_then(Value::as_array)
                .is_some_and(|versions| versions.iter().any(|value| value.as_str() == Some("2")))
        {
            return Err(attestation(
                "Phala gateway lacks the required ACI E2EE capability",
            ));
        }
        let gateway_attestation = report
            .get("attestation")
            .and_then(Value::as_object)
            .ok_or_else(|| attestation("Phala gateway attestation is missing"))?;
        if gateway_attestation.get("tee_type").and_then(Value::as_str) != Some("tdx") {
            return Err(attestation("Phala gateway is not Intel TDX"));
        }
        let keyset = gateway_attestation
            .get("workload_keyset")
            .ok_or_else(|| attestation("Phala gateway keyset is missing"))?;
        let keyset_object = object(keyset, "gateway keyset")?;
        let keyset_digest = sha256_digest(&canonical_json(keyset)?);
        if report.get("workload_keyset_digest").and_then(Value::as_str) != Some(&keyset_digest) {
            return Err(attestation("Phala gateway keyset digest mismatch"));
        }
        let report_statement = serde_json::json!({
            "keyset_digest": keyset_digest,
            "nonce": nonce,
            "purpose": "aci.report_data.v1",
        });
        let expected_report_data: [u8; 32] =
            Sha256::digest(canonical_json(&report_statement)?).into();
        if decode_32(
            "gateway report_data",
            required_str(gateway_attestation, "report_data", "gateway report data")?,
        )? != expected_report_data
        {
            return Err(attestation(
                "Phala gateway report data is not nonce/keyset bound",
            ));
        }
        let keyset_expires = keyset_object
            .get("not_after")
            .and_then(Value::as_u64)
            .ok_or_else(|| attestation("Phala gateway keyset has no expiry"))?;
        if keyset_expires <= now_unix() {
            return Err(attestation("Phala gateway keyset has expired"));
        }

        let gateway_evidence = gateway_attestation
            .get("evidence")
            .and_then(Value::as_object)
            .ok_or_else(|| attestation("Phala gateway TDX evidence is missing"))?;
        let quote = decode_hex(
            "gateway quote",
            required_str(gateway_evidence, "quote", "gateway quote")?,
        )?;
        let collateral: CollateralWire = serde_json::from_value(
            bundle
                .get("intel_collateral")
                .cloned()
                .ok_or_else(|| attestation("Phala Intel collateral is missing"))?,
        )
        .map_err(|error| attestation(format!("Phala Intel collateral is invalid: {error}")))?;
        let verified =
            rustcrypto::verify(&quote, &collateral.into_qvl()?, now_unix()).map_err(|error| {
                attestation(format!("Phala Intel DCAP verification failed: {error:#}"))
            })?;
        if verified.status != "UpToDate" {
            return Err(attestation(format!(
                "Phala gateway TDX status is {}; UpToDate is required",
                verified.status
            )));
        }
        let td = verified
            .report
            .as_td10()
            .ok_or_else(|| attestation("Phala quote is not a supported TDX report"))?;
        let mut expected_quoted_data = [0_u8; 64];
        expected_quoted_data[..32].copy_from_slice(&expected_report_data);
        if td.report_data != expected_quoted_data {
            return Err(attestation(
                "Phala TDX quote does not bind the challenged keyset",
            ));
        }
        let event_log = required_str(gateway_evidence, "event_log", "gateway event log")?;
        let app_compose = required_str(gateway_evidence, "app_compose", "gateway compose file")?;
        let (replayed_rtmr3, measured_compose_hash) = replay_rtmr3(event_log)?;
        if td.rt_mr3 != replayed_rtmr3 {
            return Err(attestation(
                "Phala gateway event log does not replay to quoted RTMR3",
            ));
        }
        if hex::encode(Sha256::digest(app_compose.as_bytes())) != measured_compose_hash {
            return Err(attestation(
                "Phala gateway compose file is not measured by the quote",
            ));
        }
        let provenance = gateway_attestation
            .get("source_provenance")
            .and_then(Value::as_object)
            .ok_or_else(|| attestation("Phala gateway source provenance is missing"))?;
        if !APPROVED_REPOSITORIES.contains(&required_str(
            provenance,
            "repo_url",
            "gateway source repository",
        )?) {
            return Err(attestation(
                "Phala gateway source repository is not approved",
            ));
        }
        let source_commit =
            required_str(provenance, "repo_commit", "gateway source commit")?.to_lowercase();
        if source_commit != APPROVED_GATEWAY_COMMIT {
            return Err(attestation("Phala gateway source commit is not approved"));
        }

        let e2ee_entries = keyset_object
            .get("e2ee_public_keys")
            .and_then(Value::as_array)
            .ok_or_else(|| attestation("Phala gateway has no E2EE keys"))?;
        let gateway_public_key_hex = e2ee_entries
            .iter()
            .filter_map(Value::as_object)
            .find(|entry| {
                entry.get("key_id").and_then(Value::as_str) == Some(E2EE_KEY_ID)
                    && entry.get("algo").and_then(Value::as_str) == Some(E2EE_ALGORITHM)
            })
            .and_then(|entry| entry.get("public_key"))
            .and_then(Value::as_str)
            .ok_or_else(|| attestation("Phala gateway has no approved X25519 E2EE key"))?
            .to_lowercase();
        decode_32("gateway X25519 key", &gateway_public_key_hex)?;
        if gateway_public_key_hex != key.model_public_key.to_lowercase() {
            return Err(attestation(
                "Phala gateway key differs from the requested attested key",
            ));
        }

        let receipt_entries = keyset_object
            .get("receipt_signing_keys")
            .and_then(Value::as_array)
            .ok_or_else(|| attestation("Phala gateway has no receipt keys"))?;
        let mut receipt_public_keys = BTreeMap::new();
        for entry in receipt_entries.iter().filter_map(Value::as_object) {
            if entry.get("algo").and_then(Value::as_str) != Some("ed25519") {
                continue;
            }
            let Some(key_id) = entry.get("key_id").and_then(Value::as_str) else {
                continue;
            };
            let Some(public_key) = entry.get("public_key").and_then(Value::as_str) else {
                continue;
            };
            if decode_32("receipt public key", public_key).is_ok() {
                receipt_public_keys.insert(key_id.to_string(), public_key.to_lowercase());
            }
        }
        if receipt_public_keys.is_empty() {
            return Err(attestation("Phala has no valid receipt key"));
        }

        let minimum_ttl = bundle
            .get("policy")
            .and_then(Value::as_object)
            .and_then(|policy| policy.get("minimum_session_ttl_seconds"))
            .and_then(Value::as_u64)
            .unwrap_or(30)
            .max(30);
        let session_values = bundle
            .get("worker_sessions")
            .and_then(Value::as_array)
            .filter(|values| !values.is_empty())
            .ok_or_else(|| attestation("Phala supplied no worker sessions"))?;
        let mut worker_sessions = BTreeMap::new();
        let mut expires_at = keyset_expires;
        for value in session_values {
            let session = verify_worker_session(value, minimum_ttl)?;
            expires_at = expires_at.min(session.expires_at);
            worker_sessions.insert(session.session_id.clone(), session);
        }
        let state = PhalaAttestationState {
            model: request.expected_model.to_string(),
            keyset_digest,
            gateway_public_key_hex: gateway_public_key_hex.clone(),
            receipt_public_keys,
            worker_sessions,
        };
        Ok(VerifiedModel {
            model_public_key_hex: gateway_public_key_hex,
            tls_fingerprint: None,
            checks: vec![
                VerificationCheck::new("gateway_tdx", "Gateway TDX", "UpToDate", true),
                VerificationCheck::new(
                    "gateway_source",
                    "Gateway workload",
                    &source_commit[..12],
                    true,
                ),
                VerificationCheck::new("gateway_keyset", "Encrypted channel", "nonce-bound", true),
                VerificationCheck::new("worker_tee", "Worker TEE", "asserted", true),
                VerificationCheck::new("worker_gpu", "Worker GPU", "asserted", true),
                VerificationCheck::new("receipt", "Signed receipt", "required", true),
            ],
            provider_state: Some(
                serde_json::to_value(state)
                    .map_err(|error| attestation(format!("Phala state failed: {error}")))?,
            ),
            expires_at_unix: Some(expires_at.saturating_sub(15)),
        })
    }
}

pub struct PhalaCipher;

impl ProviderCipher for PhalaCipher {
    fn protocol(&self) -> &'static str {
        PHALA_ACI_V2_PROTOCOL
    }

    fn encryption_version(&self) -> u8 {
        PHALA_ACI_V2_ENCRYPTION_VERSION
    }

    fn new_session(&self, verified: &VerifiedModel) -> Result<Box<dyn CipherSession>> {
        let state: PhalaAttestationState = serde_json::from_value(
            verified
                .provider_state
                .clone()
                .ok_or_else(|| provider("missing fresh locally verified Phala state"))?,
        )
        .map_err(|error| provider(format!("invalid verified Phala state: {error}")))?;
        if state.gateway_public_key_hex != verified.model_public_key_hex {
            return Err(provider("verified Phala gateway key mismatch"));
        }
        if verified
            .expires_at_unix
            .is_some_and(|expires| expires <= now_unix())
        {
            return Err(provider("verified Phala evidence has expired"));
        }
        let client_secret = StaticSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_secret);
        let mut eligible_session_ids = state
            .worker_sessions
            .iter()
            .map(|(session_id, worker)| (session_id.clone(), worker.expires_at))
            .collect::<Vec<_>>();
        eligible_session_ids.sort_by(|(left_id, left_expiry), (right_id, right_expiry)| {
            right_expiry
                .cmp(left_expiry)
                .then_with(|| left_id.cmp(right_id))
        });
        eligible_session_ids.truncate(128);
        let eligible_session_ids = eligible_session_ids
            .into_iter()
            .map(|(session_id, _)| session_id)
            .collect::<Vec<_>>();
        if eligible_session_ids.is_empty() {
            return Err(provider("Phala has no preverified worker sessions"));
        }
        Ok(Box::new(PhalaSession {
            state,
            client_secret,
            client_public_key_hex: hex::encode(client_public.as_bytes()),
            eligible_session_ids,
            nonce: random_nonce_hex(),
            timestamp: now_unix(),
            plaintext_request_hash: None,
            streamed_content: String::new(),
            streamed_reasoning: String::new(),
        }))
    }
}

struct PhalaSession {
    state: PhalaAttestationState,
    client_secret: StaticSecret,
    client_public_key_hex: String,
    eligible_session_ids: Vec<String>,
    nonce: String,
    timestamp: u64,
    plaintext_request_hash: Option<String>,
    streamed_content: String,
    streamed_reasoning: String,
}

fn request_aad(model: &str, nonce: &str, timestamp: u64, field: &str) -> Result<Vec<u8>> {
    canonical_json(&serde_json::json!({
        "purpose": "aci.e2ee.request.v2",
        "algo": E2EE_ALGORITHM,
        "model": model,
        "field": field,
        "nonce": nonce,
        "ts": timestamp,
    }))
}

fn response_aad(
    model: &str,
    nonce: &str,
    timestamp: u64,
    response_id: &str,
    field: &str,
) -> Result<Vec<u8>> {
    canonical_json(&serde_json::json!({
        "purpose": "aci.e2ee.response.v2",
        "algo": E2EE_ALGORITHM,
        "model": model,
        "id": response_id,
        "field": field,
        "nonce": nonce,
        "ts": timestamp,
    }))
}

fn derive_key(shared: &[u8; 32]) -> Result<[u8; 32]> {
    let mut key = [0_u8; 32];
    Hkdf::<Sha256>::new(None, shared)
        .expand(HKDF_INFO, &mut key)
        .map_err(|_| provider("Phala HKDF expansion failed"))?;
    Ok(key)
}

fn encrypt_field(plaintext: &[u8], recipient_hex: &str, aad: &[u8]) -> Result<String> {
    let recipient = PublicKey::from(decode_32("gateway X25519 key", recipient_hex)?);
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let key = derive_key(ephemeral_secret.diffie_hellman(&recipient).as_bytes())?;
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|_| provider("Phala AES key setup failed"))?;
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| provider("Phala request encryption failed"))?;
    Ok(hex::encode(
        [ephemeral_public.as_bytes().as_slice(), &nonce, &ciphertext].concat(),
    ))
}

fn decrypt_field(wire_hex: &str, secret: &StaticSecret, aad: &[u8]) -> Result<String> {
    let wire = hex::decode(wire_hex).map_err(|_| provider("Phala response envelope is not hex"))?;
    if wire.len() < 60 {
        return Err(provider("Phala response envelope is too short"));
    }
    let ephemeral = PublicKey::from(
        <[u8; 32]>::try_from(&wire[..32])
            .map_err(|_| provider("Phala response ephemeral key is invalid"))?,
    );
    let key = derive_key(secret.diffie_hellman(&ephemeral).as_bytes())?;
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|_| provider("Phala AES key setup failed"))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&wire[32..44]),
            Payload {
                msg: &wire[44..],
                aad,
            },
        )
        .map_err(|_| provider("Phala response decryption failed"))?;
    String::from_utf8(plaintext).map_err(|_| provider("Phala response is not UTF-8"))
}

fn append_json_member(
    output: &mut Vec<u8>,
    first: &mut bool,
    key: &str,
    value: &Value,
) -> Result<()> {
    if !*first {
        output.push(b',');
    }
    *first = false;
    output.extend_from_slice(
        &serde_json::to_vec(key).map_err(|error| provider(format!("JSON failed: {error}")))?,
    );
    output.push(b':');
    output.extend_from_slice(
        &serde_json::to_vec(value).map_err(|error| provider(format!("JSON failed: {error}")))?,
    );
    Ok(())
}

fn exact_plaintext_body(request: &PlainProviderRequest, session_ids: &[String]) -> Result<Vec<u8>> {
    if request.has_tools
        || request
            .messages
            .iter()
            .any(|message| message.has_extended_fields)
    {
        return Err(provider(
            "Phala ACI tool and extended-message fields are unavailable until their v2 AAD contract is implemented",
        ));
    }
    let mut messages = Vec::with_capacity(request.messages.len());
    for message in &request.messages {
        let mut value = Map::new();
        value.insert("role".into(), Value::String(message.role.clone()));
        if let Some(content) = &message.content {
            value.insert("content".into(), Value::String(content.clone()));
        } else if message.assistant_null_content {
            value.insert("content".into(), Value::Null);
        }
        messages.push(Value::Object(value));
    }

    let mut output = vec![b'{'];
    let mut first = true;
    append_json_member(
        &mut output,
        &mut first,
        "model",
        &Value::String(request.model.clone()),
    )?;
    append_json_member(&mut output, &mut first, "messages", &Value::Array(messages))?;
    append_json_member(
        &mut output,
        &mut first,
        "max_tokens",
        &Value::Number(request.max_tokens.into()),
    )?;
    append_json_member(
        &mut output,
        &mut first,
        "stream",
        &Value::Bool(request.stream),
    )?;
    if !first {
        output.push(b',');
    }
    first = false;
    output.extend_from_slice(b"\"provider\":{\"aci_verified\":true,\"aci_session_ids\":");
    output.extend_from_slice(
        &serde_json::to_vec(session_ids)
            .map_err(|error| provider(format!("JSON failed: {error}")))?,
    );
    output.extend_from_slice(b",\"zdr\":true}");
    if request.stream {
        append_json_member(
            &mut output,
            &mut first,
            "stream_options",
            &serde_json::json!({"include_usage": true}),
        )?;
    }
    if let Some(sampling) = &request.sampling {
        let values = sampling
            .as_object()
            .ok_or_else(|| provider("Phala sampling options are invalid"))?;
        if values.contains_key("logit_bias") {
            return Err(provider("Phala does not support logit_bias"));
        }
        for key in [
            "temperature",
            "top_p",
            "top_k",
            "min_p",
            "frequency_penalty",
            "presence_penalty",
            "stop",
            "seed",
        ] {
            if let Some(value) = values.get(key) {
                append_json_member(&mut output, &mut first, key, value)?;
            }
        }
    }
    if let Some(response_format) = &request.response_format {
        append_json_member(&mut output, &mut first, "response_format", response_format)?;
    }
    if let Some(reasoning_effort) = &request.reasoning_effort {
        append_json_member(
            &mut output,
            &mut first,
            "reasoning_effort",
            &Value::String(
                if reasoning_effort == "xhigh" {
                    "max"
                } else {
                    reasoning_effort
                }
                .to_string(),
            ),
        )?;
    }
    output.push(b'}');
    Ok(output)
}

fn receipt_event<'a>(
    receipt: &'a Map<String, Value>,
    event_type: &str,
) -> Result<&'a Map<String, Value>> {
    receipt
        .get("event_log")
        .and_then(Value::as_array)
        .and_then(|events| {
            events
                .iter()
                .filter_map(Value::as_object)
                .find(|event| event.get("type").and_then(Value::as_str) == Some(event_type))
        })
        .ok_or_else(|| provider(format!("Phala receipt omitted {event_type}")))
}

impl PhalaSession {
    fn verify_proof_bytes(&self, proof: &Value) -> Result<Vec<u8>> {
        let expected_request_hash = self
            .plaintext_request_hash
            .as_deref()
            .ok_or_else(|| provider("Phala request context was not prepared"))?;
        let proof = proof
            .as_object()
            .ok_or_else(|| provider("Phala stream omitted its proof"))?;
        let response_base64 = proof
            .get("response_body_base64")
            .and_then(Value::as_str)
            .ok_or_else(|| provider("Phala proof omitted encrypted response bytes"))?;
        let response_bytes = base64::engine::general_purpose::STANDARD
            .decode(response_base64)
            .map_err(|_| provider("Phala encrypted response base64 is invalid"))?;
        let receipt = proof
            .get("receipt")
            .and_then(Value::as_object)
            .ok_or_else(|| provider("Phala proof omitted its receipt"))?;
        if receipt.get("api_version").and_then(Value::as_str) != Some("aci/1") {
            return Err(provider("Phala receipt is not aci/1"));
        }
        if receipt
            .get("workload_keyset_digest")
            .and_then(Value::as_str)
            != Some(&self.state.keyset_digest)
            || receipt.get("model").and_then(Value::as_str) != Some(&self.state.model)
        {
            return Err(provider("Phala receipt identity mismatch"));
        }
        let key_id = receipt
            .get("key_id")
            .and_then(Value::as_str)
            .ok_or_else(|| provider("Phala receipt key id is missing"))?;
        let receipt_key = self
            .state
            .receipt_public_keys
            .get(key_id)
            .ok_or_else(|| provider("Phala receipt key was not attested"))?;
        let signature = receipt
            .get("signature")
            .and_then(Value::as_str)
            .ok_or_else(|| provider("Phala receipt signature is missing"))?;
        let signature = Signature::from_slice(
            &hex::decode(signature).map_err(|_| provider("Phala receipt signature is invalid"))?,
        )
        .map_err(|_| provider("Phala receipt signature is invalid"))?;
        let verifying_key = VerifyingKey::from_bytes(
            &decode_32("receipt public key", receipt_key)
                .map_err(|_| provider("Phala receipt public key is invalid"))?,
        )
        .map_err(|_| provider("Phala receipt public key is invalid"))?;
        let mut unsigned = receipt.clone();
        unsigned.remove("signature");
        verifying_key
            .verify(
                &canonical_json(&Value::Object(unsigned))
                    .map_err(|_| provider("Phala receipt canonicalization failed"))?,
                &signature,
            )
            .map_err(|_| provider("Phala receipt signature is invalid"))?;
        if receipt_event(receipt, "request.received")?
            .get("body_hash")
            .and_then(Value::as_str)
            != Some(expected_request_hash)
        {
            return Err(provider(
                "Phala receipt does not bind the exact local request",
            ));
        }
        if receipt_event(receipt, "response.returned")?
            .get("body_hash")
            .and_then(Value::as_str)
            != Some(&sha256_digest(&response_bytes))
        {
            return Err(provider(
                "Phala receipt does not bind the encrypted response bytes",
            ));
        }
        let upstream = receipt_event(receipt, "upstream.verified")?;
        if upstream.get("result").and_then(Value::as_str) != Some("verified")
            || upstream.get("required").and_then(Value::as_bool) != Some(true)
            || upstream
                .get("model_id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .is_none()
        {
            return Err(provider("Phala did not require a verified model worker"));
        }
        let session_id = upstream
            .get("session_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .strip_prefix("as_")
            .unwrap_or_else(|| {
                upstream
                    .get("session_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
            })
            .to_lowercase();
        if !self.eligible_session_ids.contains(&session_id) {
            return Err(provider(
                "Phala receipt cites a worker outside the preverified eligible set",
            ));
        }
        let worker = self
            .state
            .worker_sessions
            .get(&session_id)
            .ok_or_else(|| provider("Phala receipt cites a worker not preverified locally"))?;
        let served_at = receipt
            .get("served_at")
            .and_then(Value::as_u64)
            .ok_or_else(|| provider("Phala receipt served_at is invalid"))?;
        if !(worker.established_at <= served_at && served_at <= worker.expires_at) {
            return Err(provider(
                "Phala receipt falls outside the worker session lifetime",
            ));
        }
        Ok(response_bytes)
    }

    fn decrypt_verified_stream(&self, response_bytes: &[u8]) -> Result<(String, String)> {
        let raw = std::str::from_utf8(response_bytes)
            .map_err(|_| provider("Phala stream is not UTF-8 SSE"))?;
        let normalized = raw.replace("\r\n", "\n");
        let mut response_id = String::new();
        let mut content = String::new();
        let mut reasoning = String::new();
        let mut done = false;
        for frame in normalized.split("\n\n") {
            let data_lines = frame
                .lines()
                .filter_map(|line| {
                    if line == "data" {
                        Some("")
                    } else {
                        line.strip_prefix("data:")
                            .map(|value| value.strip_prefix(' ').unwrap_or(value))
                    }
                })
                .collect::<Vec<_>>();
            if data_lines.is_empty() {
                continue;
            }
            let data = data_lines.join("\n");
            if data == "[DONE]" {
                if done {
                    return Err(provider("Phala stream has duplicate completion markers"));
                }
                done = true;
                continue;
            }
            if done {
                return Err(provider("Phala stream has data after completion"));
            }
            let event: Value = serde_json::from_str(&data)
                .map_err(|_| provider("Phala stream contains invalid JSON"))?;
            let event = event
                .as_object()
                .ok_or_else(|| provider("Phala stream event is not an object"))?;
            if let Some(event_id) = event.get("id").and_then(Value::as_str) {
                if !event_id.is_empty() {
                    if !response_id.is_empty() && response_id != event_id {
                        return Err(provider("Phala stream changed response id"));
                    }
                    response_id = event_id.to_string();
                }
            }
            let Some(choices) = event.get("choices") else {
                continue;
            };
            let choices = choices
                .as_array()
                .ok_or_else(|| provider("Phala stream choices are invalid"))?;
            for (position, choice) in choices.iter().enumerate() {
                let choice = choice
                    .as_object()
                    .ok_or_else(|| provider("Phala stream choice is invalid"))?;
                let choice_index = choice
                    .get("index")
                    .and_then(Value::as_u64)
                    .unwrap_or(position as u64);
                if choice_index != 0 {
                    return Err(provider("Phala stream returned an unexpected choice"));
                }
                let Some(delta) = choice.get("delta") else {
                    continue;
                };
                let delta = delta
                    .as_object()
                    .ok_or_else(|| provider("Phala stream delta is invalid"))?;
                for member in ["content", "reasoning_content", "reasoning"] {
                    let Some(wire) = delta.get(member).and_then(Value::as_str) else {
                        continue;
                    };
                    if wire.is_empty() {
                        continue;
                    }
                    if response_id.is_empty() {
                        return Err(provider("Phala encrypted delta omitted response id"));
                    }
                    let plaintext = decrypt_field(
                        wire,
                        &self.client_secret,
                        &response_aad(
                            &self.state.model,
                            &self.nonce,
                            self.timestamp,
                            &response_id,
                            &format!("choices.{choice_index}.delta.{member}"),
                        )?,
                    )?;
                    if member == "content" {
                        content.push_str(&plaintext);
                    } else {
                        reasoning.push_str(&plaintext);
                    }
                }
            }
        }
        if !done {
            return Err(provider("Phala stream ended without its completion marker"));
        }
        if response_id.is_empty() {
            return Err(provider("Phala stream omitted its response id"));
        }
        Ok((content, reasoning))
    }
}

impl CipherSession for PhalaSession {
    fn client_public_key_hex(&self) -> Option<String> {
        Some(self.client_public_key_hex.clone())
    }

    fn is_ready(&self) -> bool {
        !self.state.worker_sessions.is_empty()
            && !self.state.receipt_public_keys.is_empty()
            && self.timestamp.saturating_add(300) >= now_unix()
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn encrypt(&mut self, _plaintext: &[u8]) -> Result<String> {
        Err(provider("Phala encryption requires field-specific AAD"))
    }

    fn decrypt(&mut self, _wire: &str) -> Result<Vec<u8>> {
        Err(provider(
            "Phala responses require receipt-gated completion decryption",
        ))
    }

    fn decrypt_stream_field(
        &mut self,
        wire: &str,
        response_id: Option<&str>,
        field: Option<&str>,
    ) -> Result<Vec<u8>> {
        let response_id = response_id
            .filter(|value| !value.is_empty())
            .ok_or_else(|| provider("Phala stream delta omitted response id"))?;
        let field = field
            .filter(|value| {
                matches!(
                    *value,
                    "choices.0.delta.content"
                        | "choices.0.delta.reasoning"
                        | "choices.0.delta.reasoning_content"
                )
            })
            .ok_or_else(|| provider("Phala stream delta has an unexpected response field"))?;
        let plaintext = decrypt_field(
            wire,
            &self.client_secret,
            &response_aad(
                &self.state.model,
                &self.nonce,
                self.timestamp,
                response_id,
                field,
            )?,
        )?;
        if field == "choices.0.delta.content" {
            self.streamed_content.push_str(&plaintext);
        } else {
            self.streamed_reasoning.push_str(&plaintext);
        }
        Ok(plaintext.into_bytes())
    }

    fn encrypt_field(&mut self, plaintext: &[u8], field: &str) -> Result<String> {
        encrypt_field(
            plaintext,
            &self.state.gateway_public_key_hex,
            &request_aad(&self.state.model, &self.nonce, self.timestamp, field)?,
        )
    }

    fn prepare_request_context(&mut self, request: &PlainProviderRequest) -> Result<Option<Value>> {
        if request.model != self.state.model {
            return Err(provider("Phala plaintext request model mismatch"));
        }
        let session_ids = self.eligible_session_ids.clone();
        let request_hash = sha256_digest(&exact_plaintext_body(request, &session_ids)?);
        self.plaintext_request_hash = Some(request_hash.clone());
        Ok(Some(serde_json::json!({
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "session_ids": session_ids,
            "keyset_digest": self.state.keyset_digest,
            "request_body_hash": request_hash,
        })))
    }

    fn decrypt_verified_completion(
        &mut self,
        completion: &RelayCompletion,
    ) -> Result<Option<DecryptedProviderCompletion>> {
        let expected_request_hash = self
            .plaintext_request_hash
            .as_deref()
            .ok_or_else(|| provider("Phala request context was not prepared"))?;
        let proof = completion
            .proof
            .as_ref()
            .and_then(Value::as_object)
            .ok_or_else(|| provider("Phala completion omitted its proof"))?;
        let response_base64 = proof
            .get("response_body_base64")
            .and_then(Value::as_str)
            .ok_or_else(|| provider("Phala proof omitted encrypted response bytes"))?;
        let response_bytes = base64::engine::general_purpose::STANDARD
            .decode(response_base64)
            .map_err(|_| provider("Phala encrypted response base64 is invalid"))?;
        let receipt_value = proof
            .get("receipt")
            .cloned()
            .ok_or_else(|| provider("Phala proof omitted its receipt"))?;
        let receipt = receipt_value
            .as_object()
            .ok_or_else(|| provider("Phala receipt is not an object"))?;
        if receipt.get("api_version").and_then(Value::as_str) != Some("aci/1") {
            return Err(provider("Phala receipt is not aci/1"));
        }
        if receipt
            .get("workload_keyset_digest")
            .and_then(Value::as_str)
            != Some(&self.state.keyset_digest)
            || receipt.get("model").and_then(Value::as_str) != Some(&self.state.model)
        {
            return Err(provider("Phala receipt identity mismatch"));
        }
        let key_id = receipt
            .get("key_id")
            .and_then(Value::as_str)
            .ok_or_else(|| provider("Phala receipt key id is missing"))?;
        let receipt_key = self
            .state
            .receipt_public_keys
            .get(key_id)
            .ok_or_else(|| provider("Phala receipt key was not attested"))?;
        let signature = receipt
            .get("signature")
            .and_then(Value::as_str)
            .ok_or_else(|| provider("Phala receipt signature is missing"))?;
        let signature = Signature::from_slice(
            &hex::decode(signature).map_err(|_| provider("Phala receipt signature is invalid"))?,
        )
        .map_err(|_| provider("Phala receipt signature is invalid"))?;
        let verifying_key = VerifyingKey::from_bytes(
            &decode_32("receipt public key", receipt_key)
                .map_err(|_| provider("Phala receipt public key is invalid"))?,
        )
        .map_err(|_| provider("Phala receipt public key is invalid"))?;
        let mut unsigned = receipt.clone();
        unsigned.remove("signature");
        verifying_key
            .verify(
                &canonical_json(&Value::Object(unsigned))
                    .map_err(|_| provider("Phala receipt canonicalization failed"))?,
                &signature,
            )
            .map_err(|_| provider("Phala receipt signature is invalid"))?;
        if receipt_event(receipt, "request.received")?
            .get("body_hash")
            .and_then(Value::as_str)
            != Some(expected_request_hash)
        {
            return Err(provider(
                "Phala receipt does not bind the exact local request",
            ));
        }
        let response_hash = sha256_digest(&response_bytes);
        if receipt_event(receipt, "response.returned")?
            .get("body_hash")
            .and_then(Value::as_str)
            != Some(&response_hash)
        {
            return Err(provider(
                "Phala receipt does not bind the encrypted response bytes",
            ));
        }
        let upstream = receipt_event(receipt, "upstream.verified")?;
        if upstream.get("result").and_then(Value::as_str) != Some("verified")
            || upstream.get("required").and_then(Value::as_bool) != Some(true)
            || upstream
                .get("model_id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .is_none()
        {
            return Err(provider("Phala did not require a verified model worker"));
        }
        let session_id = upstream
            .get("session_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .strip_prefix("as_")
            .unwrap_or_else(|| {
                upstream
                    .get("session_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
            })
            .to_lowercase();
        if !self.eligible_session_ids.contains(&session_id) {
            return Err(provider(
                "Phala receipt cites a worker outside the preverified eligible set",
            ));
        }
        let worker = self
            .state
            .worker_sessions
            .get(&session_id)
            .ok_or_else(|| provider("Phala receipt cites a worker not preverified locally"))?;
        let served_at = receipt
            .get("served_at")
            .and_then(Value::as_u64)
            .ok_or_else(|| provider("Phala receipt served_at is invalid"))?;
        if !(worker.established_at <= served_at && served_at <= worker.expires_at) {
            return Err(provider(
                "Phala receipt falls outside the worker session lifetime",
            ));
        }

        let response: Value = serde_json::from_slice(&response_bytes)
            .map_err(|error| provider(format!("Phala response JSON is invalid: {error}")))?;
        let response = response
            .as_object()
            .ok_or_else(|| provider("Phala response is not an object"))?;
        let response_id = required_str(response, "id", "response id")
            .map_err(|_| provider("Phala response id is missing"))?;
        let choice = response
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|choices| choices.first())
            .and_then(Value::as_object)
            .ok_or_else(|| provider("Phala response has no choice"))?;
        let choice_index = choice.get("index").and_then(Value::as_u64).unwrap_or(0);
        let message = choice
            .get("message")
            .and_then(Value::as_object)
            .ok_or_else(|| provider("Phala response has no message"))?;
        let decrypt_member = |member: &str| -> Result<Option<String>> {
            let Some(wire) = message.get(member).and_then(Value::as_str) else {
                return Ok(None);
            };
            if wire.is_empty() {
                return Ok(None);
            }
            Ok(Some(decrypt_field(
                wire,
                &self.client_secret,
                &response_aad(
                    &self.state.model,
                    &self.nonce,
                    self.timestamp,
                    response_id,
                    &format!("choices.{choice_index}.message.{member}"),
                )?,
            )?))
        };
        let content = decrypt_member("content")?;
        let reasoning_content = match decrypt_member("reasoning_content")? {
            Some(reasoning) => Some(reasoning),
            None => decrypt_member("reasoning")?,
        };
        if content.is_none() && reasoning_content.is_none() {
            return Err(provider("Phala completion contained no encrypted output"));
        }
        Ok(Some(DecryptedProviderCompletion {
            content,
            reasoning_content,
            refusal: None,
        }))
    }

    fn verify_stream_completion(&mut self, proof: Option<&Value>) -> Result<()> {
        let proof = proof.ok_or_else(|| provider("Phala stream omitted its final proof"))?;
        let response_bytes = self.verify_proof_bytes(proof)?;
        let (verified_content, verified_reasoning) =
            self.decrypt_verified_stream(&response_bytes)?;
        if verified_content != self.streamed_content
            || verified_reasoning != self.streamed_reasoning
        {
            return Err(provider(
                "Phala provisional deltas do not match the receipt-verified stream",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_plaintext_body_matches_aci_order() {
        let request = PlainProviderRequest {
            model: "org/model".into(),
            messages: vec![crate::provider::PlainProviderMessage {
                role: "user".into(),
                content: Some("hello".into()),
                assistant_null_content: false,
                has_extended_fields: false,
            }],
            max_tokens: 8,
            stream: false,
            sampling: None,
            response_format: None,
            reasoning_effort: None,
            has_tools: false,
        };
        let bytes = exact_plaintext_body(&request, &["aa".repeat(32)]).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            format!(
                "{{\"model\":\"org/model\",\"messages\":[{{\"role\":\"user\",\"content\":\"hello\"}}],\"max_tokens\":8,\"stream\":false,\"provider\":{{\"aci_verified\":true,\"aci_session_ids\":[\"{}\"],\"zdr\":true}}}}",
                "aa".repeat(32)
            )
        );
    }

    #[test]
    fn worker_session_rejects_wrong_content_address() {
        let value = serde_json::json!({
            "session_id": "00".repeat(32),
            "api_version": "aci/1",
            "established_at": now_unix(),
            "expires_at": now_unix() + 600,
            "claims": {
                "tee_attested": {"status": "asserted"},
                "tcb_up_to_date": {"status": "asserted"},
                "gpu_attested": {"status": "asserted"}
            },
            "channel_binding": [{"type": "e2ee_public_key_sha256"}],
            "evidence": {}
        });
        assert!(verify_worker_session(&value, 30)
            .unwrap_err()
            .to_string()
            .contains("content addressed"));
    }
}
