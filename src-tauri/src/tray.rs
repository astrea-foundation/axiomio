//! System tray: a menu to open the window, toggle the proxy, and quit. The icon tooltip reflects
//! whether the proxy is listening. Uses a color icon so Linux tray hosts do not tint transparent
//! pixels as black template art.

use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tauri::tray::{TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager};

use crate::AppState;

pub const TRAY_ID: &str = "main";
pub const APP_ICON: tauri::image::Image<'static> = tauri::include_image!("icons/icon.png");
const TRAY_ICON: tauri::image::Image<'static> = tauri::include_image!("icons/tray.png");

pub fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItemBuilder::with_id("open", "Open AxiomIO").build(app)?;
    let toggle = MenuItemBuilder::with_id("toggle", "Start / Stop proxy").build(app)?;
    let quit = MenuItemBuilder::with_id("quit", "Quit").build(app)?;
    let menu = MenuBuilder::new(app)
        .items(&[&open, &toggle, &quit])
        .build()?;

    TrayIconBuilder::with_id(TRAY_ID)
        .icon(TRAY_ICON.clone())
        .icon_as_template(false)
        .tooltip("AxiomIO")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(move |app, event| match event.id().as_ref() {
            "open" => show_main_window(app),
            "toggle" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let running = { app.state::<AppState>().server.lock().unwrap().is_some() };
                    if running {
                        let _ = crate::commands::stop_server(app.clone(), app.state::<AppState>())
                            .await;
                    } else {
                        let _ = crate::commands::start_server(app.clone(), app.state::<AppState>())
                            .await;
                    }
                });
            }
            "quit" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let handle = { app.state::<AppState>().server.lock().unwrap().take() };
                    if let Some(handle) = handle {
                        handle.stop().await;
                    }
                    app.exit(0);
                });
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { .. } = event {
                show_main_window(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

pub fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}
