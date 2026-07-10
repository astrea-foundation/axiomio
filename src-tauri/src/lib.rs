//! AxiomIO — Tauri v2 shell embedding the local OpenAI-compatible server.
//!
//! Cross-platform: the server, config, and keyring layers are OS-agnostic; the tray uses template
//! icons on macOS and appindicator on Linux; autostart uses the platform launcher.

mod commands;
mod keyring;
mod server_handle;
mod tray;
mod update;

use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use axiom_core::config::Config;
use axiom_core::relay::HttpRelay;
use axiom_server::ProxyCore;
use server_handle::ServerHandle;
use tauri::{Emitter, Manager, WindowEvent};
use tauri_plugin_autostart::MacosLauncher;

pub struct AppState {
    pub core: RwLock<Arc<ProxyCore>>,
    pub server: Mutex<Option<ServerHandle>>,
    pub config: RwLock<Config>,
    pub config_path: PathBuf,
    pub history_path: Option<PathBuf>,
}

fn set_main_window_icon(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.set_icon(tray::APP_ICON.clone());
    }
}

fn build_core(
    config: &Config,
    api_key: Option<String>,
    history_path: Option<PathBuf>,
) -> Arc<ProxyCore> {
    Arc::new(ProxyCore::new_with_history(
        Arc::new(HttpRelay::new(config.backend_url.clone())),
        api_key,
        Duration::from_secs(config.attestation_ttl_secs),
        config.default_model.clone(),
        history_path,
    ))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let config_path = Config::default_path().unwrap_or_else(|_| PathBuf::from("config.json"));
    let history_path = Config::history_path().ok();
    let config = Config::load(&config_path).unwrap_or_default();
    // Keyring may be unavailable (e.g. headless Linux); surface later via api_key_present rather
    // than failing startup or falling back to plaintext.
    let api_key = keyring::load().ok().flatten();
    let core = build_core(&config, api_key, history_path.clone());

    let state = AppState {
        core: RwLock::new(core),
        server: Mutex::new(None),
        config: RwLock::new(config.clone()),
        config_path,
        history_path,
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            tray::show_main_window(app);
        }))
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec!["--minimized"]),
        ))
        .plugin(tauri_plugin_opener::init())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::start_server,
            commands::stop_server,
            commands::get_config,
            commands::set_config,
            commands::set_api_key,
            commands::clear_api_key,
            commands::get_api_key_status,
            commands::list_models,
            commands::verify_model,
            commands::get_attestations,
            commands::get_recent_requests,
            update::check_for_update,
        ])
        .setup(move |app| {
            tray::build_tray(app.handle())?;
            commands::spawn_attestation_monitor(app.handle().clone());
            set_main_window_icon(app.handle());

            // Hide the window at launch when started minimized (autostart).
            let started_minimized = std::env::args().any(|a| a == "--minimized")
                || app
                    .state::<AppState>()
                    .config
                    .read()
                    .unwrap()
                    .start_minimized;
            if started_minimized {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            } else if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
            }

            // Auto-start the proxy in the background.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let (core, port) = {
                    let state = handle.state::<AppState>();
                    let core = state.core.read().unwrap().clone();
                    let port = state.config.read().unwrap().port;
                    (core, port)
                };
                match ServerHandle::start(core, port).await {
                    Ok(h) => {
                        *handle.state::<AppState>().server.lock().unwrap() = Some(h);
                        let _ = handle.emit(
                            "proxy://server",
                            serde_json::json!({ "state": "listening", "port": port }),
                        );
                        commands::spawn_catalog_verification(handle.clone());
                    }
                    Err(e) => {
                        let _ = handle.emit(
                            "proxy://server",
                            serde_json::json!({ "state": "error", "port": port, "error": e }),
                        );
                    }
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                let close_to_tray = window
                    .app_handle()
                    .state::<AppState>()
                    .config
                    .read()
                    .unwrap()
                    .close_to_tray;
                if close_to_tray {
                    // Hide to tray instead of quitting; real quit is via the tray menu.
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building the AxiomIO application")
        .run(|app_handle, event| {
            if let tauri::RunEvent::ExitRequested { .. } = event {
                if let Some(handle) = app_handle.state::<AppState>().server.lock().unwrap().take() {
                    // Best-effort synchronous shutdown on exit.
                    let cancel_done =
                        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let flag = cancel_done.clone();
                    tauri::async_runtime::block_on(async move {
                        handle.stop().await;
                        flag.store(true, std::sync::atomic::Ordering::Relaxed);
                    });
                }
            }
        });
}
