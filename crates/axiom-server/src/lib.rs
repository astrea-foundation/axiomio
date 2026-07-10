//! axiom-server: the local OpenAI-compatible HTTP surface. Depends on axiom-core; no Tauri.

mod audit;
pub mod command;
pub mod handlers;
mod headless;
mod history;
mod opencode;
pub mod sse;
pub mod state;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;

pub use headless::run as run_headless;
pub use state::ProxyCore;

pub fn build_router(core: Arc<ProxyCore>) -> Router {
    Router::new()
        .route("/v1/chat/completions", post(handlers::chat_completions))
        .route("/v1/models", get(handlers::list_models))
        .route("/healthz", get(handlers::healthz))
        // Local browser-based clients (e.g. web playgrounds) need permissive CORS; the bind is
        // 127.0.0.1 only, so this does not expose anything to the network.
        .layer(CorsLayer::permissive())
        .with_state(core)
}

/// Serve until `cancel` fires. Binding is done by the caller so a port-in-use error surfaces
/// synchronously rather than as a dead background task.
pub async fn serve(
    listener: tokio::net::TcpListener,
    core: Arc<ProxyCore>,
    cancel: CancellationToken,
) -> std::io::Result<()> {
    let app = build_router(core);
    axum::serve(listener, app)
        .with_graceful_shutdown(async move { cancel.cancelled().await })
        .await
}

pub async fn bind(port: u16) -> std::io::Result<tokio::net::TcpListener> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    tokio::net::TcpListener::bind(addr).await
}
