//! Lifecycle for the embedded axum server: bind-first (so port-in-use is a synchronous, typed
//! error), serve with graceful shutdown, and restart on port change.

use std::sync::Arc;

use axiom_server::{bind, serve, ProxyCore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const MISSING_API_KEY: &str = "Add an API key before starting the proxy";

pub struct ServerHandle {
    pub port: u16,
    cancel: CancellationToken,
    join: JoinHandle<std::io::Result<()>>,
}

impl ServerHandle {
    /// Bind synchronously (surfacing EADDRINUSE) then spawn the serve loop.
    pub async fn start(core: Arc<ProxyCore>, port: u16) -> Result<Self, String> {
        if core.api_key().is_none() {
            return Err(MISSING_API_KEY.into());
        }

        let listener = bind(port).await.map_err(|e| match e.kind() {
            std::io::ErrorKind::AddrInUse => format!("port {port} is already in use"),
            _ => format!("failed to bind port {port}: {e}"),
        })?;
        let cancel = CancellationToken::new();
        let c = cancel.clone();
        let join = tokio::spawn(async move { serve(listener, core, c).await });
        Ok(Self { port, cancel, join })
    }

    /// Cancel and await the serve loop, giving in-flight streams a moment to drain.
    pub async fn stop(self) {
        self.cancel.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), self.join).await;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axiom_core::relay::HttpRelay;

    use super::*;

    #[tokio::test]
    async fn start_requires_api_key() {
        let core = Arc::new(ProxyCore::new(
            Arc::new(HttpRelay::new("http://127.0.0.1:9")),
            None,
            Duration::from_secs(60),
            None,
        ));

        match ServerHandle::start(core, 0).await {
            Err(err) => assert_eq!(err, MISSING_API_KEY),
            Ok(handle) => {
                handle.stop().await;
                panic!("server started without an API key");
            }
        }
    }
}
