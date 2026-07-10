fn main() {
    if std::env::args_os().len() == 1 {
        hide_windows_console();
        axiom_proxy_lib::run();
        return;
    }

    if let Err(error) = axiom_server::command::run(std::env::args_os()) {
        eprintln!("axiomio: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn hide_windows_console() {
    use windows_sys::Win32::System::Console::GetConsoleWindow;
    use windows_sys::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_HIDE};

    unsafe {
        let window = GetConsoleWindow();
        if !window.is_null() {
            ShowWindow(window, SW_HIDE);
        }
    }
}

#[cfg(not(windows))]
fn hide_windows_console() {}
