//! Tauri command surface — the contract the React UI invokes. All state changes persist config
//! and, where relevant, restart the embedded server.

use std::sync::Arc;
use std::time::Duration;

use axiom_core::config::Config;
use axiom_core::events::{AttestationSummary, RequestLogEntry};
use axiom_core::relay::{HttpRelay, RelayApi, RelayModel};
use axiom_server::ProxyCore;
use serde::Serialize;
use std::sync::atomic::Ordering;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::server_handle::ServerHandle;
use crate::{keyring, AppState};

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProxyStatus {
    pub running: bool,
    pub port: u16,
    pub base_url: String,
    pub api_key_present: bool,
    pub active_requests: u32,
    pub total_requests: u64,
    pub total_prompt_tokens: u64,
    pub total_completion_tokens: u64,
    pub version: String,
    pub error: Option<String>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyStatus {
    pub present: bool,
    pub masked: Option<String>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ModelInfo {
    pub id: String,
    pub label: String,
    pub model: String,
    pub base_url: String,
}

fn status_of(state: &AppState) -> ProxyStatus {
    let config = state.config.read().unwrap().clone();
    let core = state.core.read().unwrap().clone();
    let running = state.server.lock().unwrap().is_some();
    ProxyStatus {
        running,
        port: config.port,
        base_url: config.base_url(),
        api_key_present: core.api_key().is_some(),
        active_requests: core.counters.active_requests.load(Ordering::Relaxed),
        total_requests: core.counters.total_requests.load(Ordering::Relaxed),
        total_prompt_tokens: core.counters.prompt_tokens.load(Ordering::Relaxed),
        total_completion_tokens: core.counters.completion_tokens.load(Ordering::Relaxed),
        version: env!("CARGO_PKG_VERSION").to_string(),
        error: state.last_error.read().unwrap().clone(),
    }
}

pub(crate) fn emit_status(app: &AppHandle) {
    let state = app.state::<AppState>();
    let _ = app.emit("proxy://status", status_of(&state));
}

#[tauri::command]
pub fn get_status(state: State<AppState>) -> ProxyStatus {
    status_of(&state)
}

#[tauri::command]
pub async fn start_server(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<ProxyStatus, String> {
    {
        if state.server.lock().unwrap().is_some() {
            return Ok(status_of(&state));
        }
    }
    let (core, port) = {
        let core = state.core.read().unwrap().clone();
        let port = state.config.read().unwrap().port;
        (core, port)
    };
    if let Err(error) = core.refresh_models().await {
        let error = format!("Backend validation failed: {error}");
        *state.last_error.write().unwrap() = Some(error.clone());
        emit_status(&app);
        return Err(error);
    }
    let handle = match ServerHandle::start(core, port).await {
        Ok(handle) => handle,
        Err(error) => {
            *state.last_error.write().unwrap() = Some(error.clone());
            emit_status(&app);
            return Err(error);
        }
    };
    *state.server.lock().unwrap() = Some(handle);
    *state.last_error.write().unwrap() = None;
    emit_status(&app);
    let _ = app.emit(
        "proxy://server",
        serde_json::json!({ "state": "listening", "port": port }),
    );
    spawn_catalog_verification(app.clone());
    Ok(status_of(&state))
}

#[tauri::command]
pub async fn stop_server(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<ProxyStatus, String> {
    let handle = state.server.lock().unwrap().take();
    if let Some(handle) = handle {
        handle.stop().await;
    }
    *state.last_error.write().unwrap() = None;
    emit_status(&app);
    let _ = app.emit("proxy://server", serde_json::json!({ "state": "stopped" }));
    Ok(status_of(&state))
}

#[tauri::command]
pub fn get_config(state: State<AppState>) -> Config {
    state.config.read().unwrap().clone()
}

/// Apply a partial config (JSON object), persist it, and restart the server if the port or backend
/// changed. Rebuilds the ProxyCore (new relay) when the backend URL changes.
#[tauri::command]
pub async fn set_config(
    app: AppHandle,
    state: State<'_, AppState>,
    patch: serde_json::Value,
) -> Result<Config, String> {
    let (old_backend, new_config) = {
        let mut config = state.config.write().unwrap();
        let old_backend = config.backend_url.clone();
        let mut as_value = serde_json::to_value(&*config).map_err(|e| e.to_string())?;
        if let (Some(obj), Some(p)) = (as_value.as_object_mut(), patch.as_object()) {
            for (k, v) in p {
                obj.insert(k.clone(), v.clone());
            }
        }
        *config = serde_json::from_value(as_value).map_err(|e| e.to_string())?;
        (old_backend, config.clone())
    };
    new_config
        .save(&state.config_path)
        .map_err(|e| e.to_string())?;

    let backend_changed = new_config.backend_url != old_backend;
    if backend_changed {
        // Rebuild core against the new backend, preserving the API key + TTL.
        let api_key = state.core.read().unwrap().api_key();
        let relay = Arc::new(HttpRelay::new(new_config.backend_url.clone()));
        let core = Arc::new(ProxyCore::new_with_history(
            relay,
            api_key,
            Duration::from_secs(new_config.attestation_ttl_secs),
            new_config.default_model.clone(),
            state.history_path.clone(),
        ));
        *state.core.write().unwrap() = core;
    }

    let was_running = {
        let handle = state.server.lock().unwrap().take();
        if let Some(handle) = handle {
            handle.stop().await;
            true
        } else {
            false
        }
    };
    // If it was running, restart on the (possibly new) port with the (possibly rebuilt) core.
    if was_running {
        let core = state.core.read().unwrap().clone();
        if let Err(error) = core.refresh_models().await {
            let error = format!("Backend validation failed: {error}");
            *state.last_error.write().unwrap() = Some(error.clone());
            emit_status(&app);
            return Err(error);
        }
        let handle = ServerHandle::start(core, new_config.port).await?;
        *state.server.lock().unwrap() = Some(handle);
        *state.last_error.write().unwrap() = None;
        spawn_catalog_verification(app.clone());
    }
    emit_status(&app);
    Ok(new_config)
}

#[tauri::command]
pub async fn set_api_key(
    app: AppHandle,
    state: State<'_, AppState>,
    key: String,
) -> Result<ApiKeyStatus, String> {
    let key = key.trim().to_string();
    if !key.starts_with("axm_") {
        return Err("API keys start with axm_".into());
    }
    let backend_url = state.config.read().unwrap().backend_url.clone();
    HttpRelay::new(backend_url)
        .list_models(&key)
        .await
        .map_err(|e| format!("API key validation failed: {e}"))?;

    keyring::store(&key)?;
    let core = state.core.read().unwrap().clone();
    core.set_api_key(Some(key.clone()));
    *state.last_error.write().unwrap() = None;
    emit_status(&app);
    if state.server.lock().unwrap().is_some() {
        spawn_catalog_verification(app.clone());
    }
    Ok(mask(&key))
}

#[tauri::command]
pub async fn clear_api_key(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    keyring::clear()?;
    let handle = state.server.lock().unwrap().take();
    if let Some(handle) = handle {
        handle.stop().await;
        let _ = app.emit("proxy://server", serde_json::json!({ "state": "stopped" }));
    }
    state.core.read().unwrap().set_api_key(None);
    *state.last_error.write().unwrap() = None;
    emit_status(&app);
    Ok(())
}

#[tauri::command]
pub fn get_api_key_status(state: State<AppState>) -> ApiKeyStatus {
    match state.core.read().unwrap().api_key() {
        Some(key) => mask(&key),
        None => ApiKeyStatus {
            present: false,
            masked: None,
        },
    }
}

fn mask(key: &str) -> ApiKeyStatus {
    let tail: String = key
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    ApiKeyStatus {
        present: true,
        masked: Some(format!("axm_…{tail}")),
    }
}

#[tauri::command]
pub async fn list_models(state: State<'_, AppState>) -> Result<Vec<ModelInfo>, String> {
    let core = state.core.read().unwrap().clone();
    let models = core.refresh_models().await.map_err(|e| e.to_string())?;
    Ok(models
        .into_iter()
        .map(|m| ModelInfo {
            id: m.id,
            label: m.label,
            model: m.model,
            base_url: m.base_url,
        })
        .collect())
}

fn summary(
    model_id: &str,
    base_url: &str,
    provider: &str,
    v: &axiom_core::provider::VerifiedModel,
) -> AttestationSummary {
    AttestationSummary {
        model_id: model_id.to_string(),
        base_url: base_url.to_string(),
        provider: provider.to_string(),
        verified: true,
        model_pubkey_hex: Some(v.model_public_key_hex.clone()),
        tls_fingerprint: v.tls_fingerprint.clone(),
        checks: v.checks.clone(),
        error: None,
    }
}

fn failed_summary(model: &RelayModel, error: impl ToString) -> AttestationSummary {
    AttestationSummary {
        model_id: model.id.clone(),
        base_url: model.base_url.clone(),
        provider: model.provider.clone(),
        verified: false,
        model_pubkey_hex: None,
        tls_fingerprint: None,
        checks: Vec::new(),
        error: Some(error.to_string()),
    }
}

async fn verify_catalog_once(app: AppHandle, core: Arc<ProxyCore>) {
    let models = match core.refresh_models().await {
        Ok(models) => models,
        Err(_) => return,
    };

    for model in models {
        match core.ensure_verified(&model).await {
            Ok(v) => {
                let _ = app.emit(
                    "proxy://attestation",
                    summary(&model.id, &model.base_url, &model.provider, &v),
                );
            }
            Err(e) => {
                core.invalidate_attestation(&model.id);
                let _ = app.emit("proxy://attestation", failed_summary(&model, e));
            }
        }
    }
}

pub fn spawn_catalog_verification(app: AppHandle) {
    let core = app.state::<AppState>().core.read().unwrap().clone();
    tauri::async_runtime::spawn(verify_catalog_once(app, core));
}

pub fn spawn_attestation_monitor(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            let (running, has_key, ttl_secs, core) = {
                let state = app.state::<AppState>();
                let running = state.server.lock().unwrap().is_some();
                let core = state.core.read().unwrap().clone();
                let has_key = core.api_key().is_some();
                let ttl_secs = state.config.read().unwrap().attestation_ttl_secs.max(30);
                (running, has_key, ttl_secs, core)
            };

            if running && has_key {
                verify_catalog_once(app.clone(), core).await;
            }

            tokio::time::sleep(Duration::from_secs(ttl_secs)).await;
        }
    });
}

#[tauri::command]
pub async fn verify_model(
    app: AppHandle,
    state: State<'_, AppState>,
    model_id: String,
    force: bool,
) -> Result<AttestationSummary, String> {
    let core = state.core.read().unwrap().clone();
    if force {
        core.invalidate_attestation(&model_id);
    }
    let model = core
        .resolve_model(&model_id)
        .await
        .map_err(|e| e.to_string())?;
    match core.ensure_verified(&model).await {
        Ok(v) => {
            let s = summary(&model.id, &model.base_url, &model.provider, &v);
            let _ = app.emit("proxy://attestation", s.clone());
            Ok(s)
        }
        Err(e) => {
            let s = failed_summary(&model, e);
            let _ = app.emit("proxy://attestation", s.clone());
            Ok(s)
        }
    }
}

#[tauri::command]
pub fn get_attestations(state: State<AppState>) -> Vec<AttestationSummary> {
    let core = state.core.read().unwrap().clone();
    core.cached_attestations()
        .into_iter()
        .map(|(id, v)| {
            let (base_url, provider) = core
                .model_info(&id)
                .map(|m| (m.base_url, m.provider))
                .unwrap_or_default();
            summary(&id, &base_url, &provider, &v)
        })
        .collect()
}

#[tauri::command]
pub fn get_recent_requests(state: State<AppState>, limit: usize) -> Vec<RequestLogEntry> {
    state.core.read().unwrap().recent_requests(limit.min(100))
}
