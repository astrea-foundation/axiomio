//! API key storage in the OS keyring (macOS Keychain, Windows Credential Manager, Linux Secret
//! Service). Never falls back to a plaintext file — if the keyring is unavailable, that surfaces
//! to the UI so the user knows the key isn't persisted.

use keyring::Entry;

const SERVICE: &str = "axiom-proxy";
const ACCOUNT: &str = "api-key";

fn entry() -> Result<Entry, String> {
    Entry::new(SERVICE, ACCOUNT).map_err(|e| format!("keyring unavailable: {e}"))
}

pub fn load() -> Result<Option<String>, String> {
    match entry()?.get_password() {
        Ok(secret) => Ok(Some(secret)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("keyring read failed: {e}")),
    }
}

pub fn store(key: &str) -> Result<(), String> {
    entry()?
        .set_password(key)
        .map_err(|e| format!("keyring write failed: {e}"))
}

pub fn clear() -> Result<(), String> {
    match entry()?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("keyring delete failed: {e}")),
    }
}
