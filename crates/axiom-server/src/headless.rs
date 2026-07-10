//! Headless proxy: runs the OpenAI-compatible server without the Tauri shell, driving the real
//! backend. This is the dev/CI harness — point curl or the openai SDK at http://127.0.0.1:<port>/v1.
//!
//! Env:
//!   AXIOM_PROXY_API_KEY   (required)  the axm_... relay key
//!   AXIOM_PROXY_BACKEND   (optional)  backend base url (default from Config)
//!   AXIOM_PROXY_PORT      (optional)  listen port (default 8484)

use std::sync::Arc;
use std::time::Duration;

use crate::{bind, serve, ProxyCore};
use axiom_core::config::Config;
use axiom_core::relay::HttpRelay;
use tokio_util::sync::CancellationToken;

pub async fn run() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let mut config = Config::default();
    if let Ok(backend) = std::env::var("AXIOM_PROXY_BACKEND") {
        config.backend_url = backend;
    }
    if let Ok(port) = std::env::var("AXIOM_PROXY_PORT") {
        config.port = port.parse().unwrap_or(config.port);
    }
    let api_key = std::env::var("AXIOM_PROXY_API_KEY").ok();
    if api_key.is_none() {
        tracing::warn!("AXIOM_PROXY_API_KEY not set — requests will 401 until one is configured");
    }

    let relay = Arc::new(HttpRelay::new(config.backend_url.clone()));
    let history_path = Config::history_path().ok();
    let core = Arc::new(ProxyCore::new_with_history(
        relay,
        api_key,
        Duration::from_secs(config.attestation_ttl_secs),
        config.default_model.clone(),
        history_path,
    ));

    let listener = bind(config.port).await?;
    tracing::info!("axiom proxy listening on {}", config.base_url());

    let cancel = CancellationToken::new();
    let shutdown = cancel.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        shutdown.cancel();
    });
    serve(listener, core, cancel).await?;
    Ok(())
}
