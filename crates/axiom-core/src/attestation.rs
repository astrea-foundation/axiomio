//! Local TEE attestation verification — a port of `verification/near_verifier.py`.
//!
//! Split into a PURE `verify_report` (all checks that are functions of already-fetched inputs, so
//! they unit-test without any network) and network steps (`fetch_report`, TDX collateral fetch via
//! dcap-qvl, NVIDIA NRAS). The attested ed25519 signing key IS the E2EE model key; it is bound to
//! the TDX quote's `report_data` and to the live TLS SPKI, so encrypting to it is safe only when
//! the live connection presents that same SPKI.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::{de::Error as DeError, Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use crate::e2ee::verify_report_data;
use crate::error::{CoreError, Result};
use crate::provider::{VerificationCheck, VerifiedModel};
use crate::providers::near::is_near_gateway;

const NRAS_URL: &str = "https://nras.attestation.nvidia.com/v3/attest/gpu";
const INTEL_PCCS: &str = "https://api.trustedservices.intel.com/";

/// The attestation report as returned by `{base_url}/attestation/report`.
#[derive(Debug, Clone, Deserialize)]
pub struct AttestationReport {
    #[serde(default)]
    pub signing_algo: Option<String>,
    #[serde(default)]
    pub signing_public_key: Option<String>,
    #[serde(default)]
    pub signing_address: Option<String>,
    #[serde(default, alias = "request_nonce")]
    pub nonce: Option<String>,
    #[serde(default, alias = "tls_cert_fingerprint")]
    pub tls_fingerprint: Option<String>,
    #[serde(default)]
    pub model_name: Option<String>,
    #[serde(default, alias = "intel_quote")]
    pub intel_quote: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nvidia_payload")]
    pub nvidia_payload: Option<serde_json::Value>,
}

/// NEAR's attestation surface as ordered display checks. Only constructed on the success path,
/// where the TLS binding already held and both hardware statuses were accepted.
pub fn near_checks(intel_status: &str, nvidia_status: &str) -> Vec<VerificationCheck> {
    vec![
        VerificationCheck::new("tls_binding", "TLS binding", "bound", true),
        VerificationCheck::new(
            "intel_tdx",
            "Intel TDX",
            intel_status,
            matches!(intel_status, "UpToDate" | "SWHardeningNeeded"),
        ),
        VerificationCheck::new(
            "nvidia_gpu",
            "NVIDIA GPU",
            nvidia_status,
            nvidia_status == "verified",
        ),
    ]
}

/// Normalize a hex-or-base64 quote string to raw bytes (mirrors `quote_to_hex`).
fn decode_quote(value: &str) -> Result<Vec<u8>> {
    let stripped = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    if let Ok(bytes) = hex::decode(stripped) {
        return Ok(bytes);
    }
    base64::engine::general_purpose::STANDARD
        .decode(stripped.as_bytes())
        .map_err(|e| CoreError::Attestation(format!("quote is neither hex nor base64: {e}")))
}

/// SHA-256 of the leaf certificate's SubjectPublicKeyInfo (DER). This is what the attestation
/// binds as `tls_cert_fingerprint`, and what we independently compute from the live connection.
pub fn spki_sha256(leaf_cert_der: &[u8]) -> Result<String> {
    let (_, cert) = X509Certificate::from_der(leaf_cert_der)
        .map_err(|e| CoreError::Attestation(format!("bad leaf cert: {e}")))?;
    let spki_der = cert.public_key().raw;
    Ok(hex::encode(Sha256::digest(spki_der)))
}

fn strip_hex(value: &str) -> String {
    value.trim().trim_start_matches("0x").to_lowercase()
}

fn deserialize_nvidia_payload<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<serde_json::Value>, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<serde_json::Value>::deserialize(deserializer)? {
        Some(serde_json::Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(serde_json::Value::String(s)) => serde_json::from_str(&s)
            .map(Some)
            .map_err(|e| D::Error::custom(format!("nvidia_payload string is not JSON: {e}"))),
        other => Ok(other),
    }
}

/// PURE verification: everything that is a function of the fetched report, the live SPKI hash, our
/// nonce, and the expected model. TDX and NVIDIA statuses are computed by the callers and passed
/// in, since those require network. Returns the verified model key.
pub fn verify_report(
    report: &AttestationReport,
    live_spki_hash: &str,
    expected_nonce: &str,
    expected_model: &str,
    intel_status: &str,
    nvidia_status: &str,
) -> Result<VerifiedModel> {
    // Algorithm must be the ed25519 E2EE variant.
    if report.signing_algo.as_deref() != Some("ed25519") {
        return Err(CoreError::Attestation(
            "report is not ed25519 (E2EE) signed".into(),
        ));
    }

    // The E2EE key is signing_public_key (falling back to signing_address).
    let key = report
        .signing_public_key
        .clone()
        .or_else(|| report.signing_address.clone())
        .map(|k| strip_hex(&k))
        .ok_or_else(|| CoreError::Attestation("no signing public key in report".into()))?;
    if key.len() != 64 || hex::decode(&key).is_err() {
        return Err(CoreError::Attestation(
            "signing public key is not 32-byte hex".into(),
        ));
    }

    // Nonce freshness (case-insensitive).
    match report.nonce.as_deref() {
        Some(n) if n.eq_ignore_ascii_case(expected_nonce) => {}
        Some(_) => return Err(CoreError::Attestation("attestation nonce mismatch".into())),
        None => return Err(CoreError::Attestation("attestation missing nonce".into())),
    }

    // Model binding, when present.
    if let Some(name) = report.model_name.as_deref() {
        if name != expected_model {
            return Err(CoreError::Attestation(format!(
                "attested model {name} != requested {expected_model}"
            )));
        }
    }

    // Live TLS SPKI must equal the attested fingerprint (binds the connection to the evidence).
    let fp = report
        .tls_fingerprint
        .as_deref()
        .map(strip_hex)
        .ok_or_else(|| CoreError::Attestation("attestation missing tls fingerprint".into()))?;
    if fp != strip_hex(live_spki_hash) {
        return Err(CoreError::Attestation(
            "live TLS SPKI does not match attested fingerprint".into(),
        ));
    }

    // Both hardware checks must have passed (or been explicitly skipped upstream — we require real
    // statuses for the E2EE path).
    if !matches!(intel_status, "UpToDate" | "SWHardeningNeeded") {
        return Err(CoreError::Attestation(format!(
            "TDX status not acceptable: {intel_status}"
        )));
    }
    if nvidia_status != "verified" {
        return Err(CoreError::Attestation(format!(
            "GPU status not verified: {nvidia_status}"
        )));
    }

    Ok(VerifiedModel {
        model_public_key_hex: key,
        tls_fingerprint: Some(fp),
        checks: near_checks(intel_status, nvidia_status),
    })
}

/// Verify the Intel TDX quote via dcap-qvl (fetches collateral from Intel PCS), then check that
/// the TD `report_data` binds our signing key + TLS fingerprint + nonce. Returns the TCB status.
pub async fn verify_tdx(
    quote_str: &str,
    signing_key_hex: &str,
    tls_fingerprint_hex: &str,
    nonce_hex: &str,
) -> Result<String> {
    let quote = decode_quote(quote_str)?;
    let client = dcap_qvl::collateral::CollateralClient::with_default_http(INTEL_PCCS)
        .map_err(|e| CoreError::Attestation(format!("collateral client: {e:?}")))?;
    let verified = client
        .fetch_and_verify(&quote)
        .await
        .map_err(|e| CoreError::Attestation(format!("TDX verify failed: {e:?}")))?;

    let td = verified
        .report
        .as_td10()
        .ok_or_else(|| CoreError::Attestation("quote is not a TD10 report".into()))?;

    let report_data_hex = hex::encode(td.report_data);
    if !verify_report_data(
        &report_data_hex,
        signing_key_hex,
        tls_fingerprint_hex,
        nonce_hex,
    )? {
        return Err(CoreError::Attestation(
            "TDX report_data binding mismatch".into(),
        ));
    }
    Ok(verified.status)
}

/// Verify the NVIDIA GPU attestation via NRAS: POST the payload, decode the returned JWT payload,
/// and check the overall result and eat_nonce. Mirrors `verify_gpu_attestation`.
pub async fn verify_gpu(
    http: &reqwest::Client,
    payload: &serde_json::Value,
    expected_nonce: &str,
) -> Result<String> {
    // The payload's own nonce must match ours before we trust the round trip.
    if let Some(n) = payload.get("nonce").and_then(|v| v.as_str()) {
        if !n.eq_ignore_ascii_case(expected_nonce) {
            return Err(CoreError::Attestation("GPU payload nonce mismatch".into()));
        }
    }
    let resp = http.post(NRAS_URL).json(payload).send().await?;
    if !resp.status().is_success() {
        return Err(CoreError::Attestation(format!(
            "NRAS returned {}",
            resp.status()
        )));
    }
    let nras: serde_json::Value = resp.json().await?;
    // Response is a list of [label, JWT]; take the first JWT.
    let jwt = nras
        .get(0)
        .and_then(|entry| entry.get(1))
        .and_then(|v| v.as_str())
        .ok_or_else(|| CoreError::Attestation("NRAS response missing JWT".into()))?;
    let verdict = decode_jwt_payload(jwt)?;

    let overall = verdict.get("x-nvidia-overall-att-result");
    let ok = matches!(
        overall,
        Some(serde_json::Value::Bool(true)) | Some(serde_json::Value::String(_))
    ) && overall
        .map(|v| match v {
            serde_json::Value::Bool(b) => *b,
            serde_json::Value::String(s) => {
                matches!(s.as_str(), "true" | "success" | "PASS" | "pass")
            }
            _ => false,
        })
        .unwrap_or(false);
    if !ok {
        return Err(CoreError::Attestation(
            "GPU overall attestation result not success".into(),
        ));
    }
    match verdict.get("eat_nonce").and_then(|v| v.as_str()) {
        Some(n) if n.eq_ignore_ascii_case(expected_nonce) => Ok("verified".to_string()),
        _ => Err(CoreError::Attestation("GPU eat_nonce mismatch".into())),
    }
}

fn decode_jwt_payload(jwt: &str) -> Result<serde_json::Value> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() < 2 {
        return Err(CoreError::Attestation("malformed JWT".into()));
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| CoreError::Attestation(format!("bad JWT payload b64: {e}")))?;
    serde_json::from_slice(&bytes).map_err(|e| CoreError::Attestation(format!("bad JWT json: {e}")))
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random_nonce_hex() -> String {
    use rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Normalize the attestation payload: some gateways wrap per-model reports in `model_attestations`.
fn normalize_report(value: serde_json::Value) -> serde_json::Value {
    if let Some(arr) = value.get("model_attestations").and_then(|v| v.as_array()) {
        if let Some(first) = arr.first().cloned() {
            let mut merged = first;
            if let (Some(m), Some(top)) = (merged.as_object_mut(), value.as_object()) {
                for (k, v) in top {
                    if k != "model_attestations" {
                        m.entry(k.clone()).or_insert_with(|| v.clone());
                    }
                }
            }
            return merged;
        }
    }
    value
}

/// Fetch `{base_url}/attestation/report` and, from the SAME TLS connection the report arrived on,
/// compute the live leaf-cert SPKI hash. Returns (report, live_spki_hex, nonce).
pub async fn fetch_report(
    base_url: &str,
    model: &str,
) -> Result<(AttestationReport, String, String)> {
    let nonce = random_nonce_hex();
    let base = base_url.trim_end_matches('/');
    let mut url = format!(
        "{base}/attestation/report?signing_algo=ed25519&nonce={nonce}&include_tls_fingerprint=true"
    );
    // The multi-model gateway needs an explicit model selector; per-model hosts do not.
    if is_near_gateway(base) {
        url.push_str(&format!("&model={model}"));
    }

    let client = reqwest::Client::builder()
        .tls_info(true)
        .timeout(std::time::Duration::from_secs(60))
        .build()?;
    let resp = client
        .get(&url)
        .header("accept", "application/json")
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(CoreError::Attestation(format!(
            "report fetch returned {}",
            resp.status()
        )));
    }

    // Leaf cert of the exact connection the evidence travelled over (closes a TOCTOU vs. a
    // separate probe connection).
    let leaf_der = resp
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|info| info.peer_certificate())
        .ok_or_else(|| CoreError::Attestation("no peer certificate on the TLS connection".into()))?
        .to_vec();
    let live_spki = spki_sha256(&leaf_der)?;

    let raw: serde_json::Value = resp.json().await?;
    let normalized = normalize_report(raw);
    let report: AttestationReport = serde_json::from_value(normalized)
        .map_err(|e| CoreError::Attestation(format!("bad report json: {e}")))?;
    Ok((report, live_spki, nonce))
}

/// Full local verification for one model: fetch the report over TLS, verify the TDX quote and the
/// GPU attestation, and bind the model key to both the quote and the live TLS SPKI. Fail-closed.
pub async fn verify_model(base_url: &str, expected_model: &str) -> Result<VerifiedModel> {
    let (report, live_spki, nonce) = fetch_report(base_url, expected_model).await?;

    let key = report
        .signing_public_key
        .clone()
        .or_else(|| report.signing_address.clone())
        .map(|k| strip_hex(&k))
        .ok_or_else(|| CoreError::Attestation("no signing public key in report".into()))?;
    let fp = report
        .tls_fingerprint
        .as_deref()
        .map(strip_hex)
        .ok_or_else(|| CoreError::Attestation("attestation missing tls fingerprint".into()))?;

    let quote = report
        .intel_quote
        .as_deref()
        .ok_or_else(|| CoreError::Attestation("attestation missing intel quote".into()))?;
    let intel_status = verify_tdx(quote, &key, &fp, &nonce).await?;

    let http = reqwest::Client::new();
    let payload = report
        .nvidia_payload
        .as_ref()
        .ok_or_else(|| CoreError::Attestation("attestation missing nvidia payload".into()))?;
    let nvidia_status = verify_gpu(&http, payload, &nonce).await?;

    verify_report(
        &report,
        &live_spki,
        &nonce,
        expected_model,
        &intel_status,
        &nvidia_status,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_report() -> AttestationReport {
        AttestationReport {
            signing_algo: Some("ed25519".into()),
            signing_public_key: Some("aa".repeat(32)),
            signing_address: None,
            nonce: Some("NONCE123".into()),
            tls_fingerprint: Some("56".repeat(32)),
            model_name: Some("test-model".into()),
            intel_quote: None,
            nvidia_payload: None,
        }
    }

    #[test]
    fn parses_nvidia_payload_json_string() {
        let report: AttestationReport = serde_json::from_value(serde_json::json!({
            "nvidia_payload": "{\"nonce\":\"abc123\",\"evidence_list\":[]}"
        }))
        .unwrap();

        let payload = report.nvidia_payload.unwrap();
        assert_eq!(payload["nonce"], "abc123");
        assert!(payload["evidence_list"].is_array());
    }

    #[test]
    fn parses_nvidia_payload_object() {
        let report: AttestationReport = serde_json::from_value(serde_json::json!({
            "nvidia_payload": {
                "nonce": "abc123",
                "evidence_list": []
            }
        }))
        .unwrap();

        let payload = report.nvidia_payload.unwrap();
        assert_eq!(payload["nonce"], "abc123");
        assert!(payload["evidence_list"].is_array());
    }

    #[test]
    fn verify_report_accepts_bound_evidence() {
        let r = base_report();
        let v = verify_report(
            &r,
            &"56".repeat(32),
            "nonce123",
            "test-model",
            "UpToDate",
            "verified",
        )
        .unwrap();
        assert_eq!(v.model_public_key_hex, "aa".repeat(32));
    }

    #[test]
    fn rejects_tls_fingerprint_mismatch() {
        let r = base_report();
        let err = verify_report(
            &r,
            &"99".repeat(32),
            "nonce123",
            "test-model",
            "UpToDate",
            "verified",
        );
        assert!(err.is_err());
    }

    #[test]
    fn rejects_nonce_mismatch() {
        let r = base_report();
        assert!(verify_report(
            &r,
            &"56".repeat(32),
            "different",
            "test-model",
            "UpToDate",
            "verified"
        )
        .is_err());
    }

    #[test]
    fn rejects_wrong_model() {
        let r = base_report();
        assert!(verify_report(
            &r,
            &"56".repeat(32),
            "nonce123",
            "other-model",
            "UpToDate",
            "verified"
        )
        .is_err());
    }

    #[test]
    fn rejects_bad_tdx_or_gpu_status() {
        let r = base_report();
        assert!(verify_report(
            &r,
            &"56".repeat(32),
            "nonce123",
            "test-model",
            "OutOfDate",
            "verified"
        )
        .is_err());
        assert!(verify_report(
            &r,
            &"56".repeat(32),
            "nonce123",
            "test-model",
            "UpToDate",
            "skipped"
        )
        .is_err());
    }

    #[test]
    fn rejects_non_ed25519() {
        let mut r = base_report();
        r.signing_algo = Some("ecdsa".into());
        assert!(verify_report(
            &r,
            &"56".repeat(32),
            "nonce123",
            "test-model",
            "UpToDate",
            "verified"
        )
        .is_err());
    }

    #[test]
    fn decode_quote_handles_hex_and_base64() {
        assert_eq!(
            decode_quote("0xdeadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            decode_quote("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        // base64 of "hi" is "aGk="
        assert_eq!(decode_quote("aGk=").unwrap(), b"hi".to_vec());
    }
}
