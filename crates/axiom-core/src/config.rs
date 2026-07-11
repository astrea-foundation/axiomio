//! Persistent proxy configuration. Stored as JSON at the platform config dir via `directories`
//! (Linux: ~/.config/axiom-proxy, macOS: ~/Library/Application Support, Windows: %APPDATA%),
//! so behavior is identical for the desktop app and `--headless` mode. The API key is NEVER here
//! — it lives in the OS keyring.

use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};

fn default_port() -> u16 {
    8484
}
fn default_backend_url() -> String {
    "https://api.axiom.stream".to_string()
}

const LEGACY_DEVELOPMENT_BACKEND_URL: &str = "http://127.0.0.1:8080";
const CURRENT_CONFIG_VERSION: u32 = 1;
fn default_attestation_ttl() -> u64 {
    900
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_backend_url")]
    pub backend_url: String,
    #[serde(default = "default_attestation_ttl")]
    pub attestation_ttl_secs: u64,
    #[serde(default)]
    pub default_model: Option<String>,
    #[serde(default)]
    pub start_minimized: bool,
    #[serde(default = "default_true")]
    pub close_to_tray: bool,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: CURRENT_CONFIG_VERSION,
            port: default_port(),
            backend_url: default_backend_url(),
            attestation_ttl_secs: default_attestation_ttl(),
            default_model: None,
            start_minimized: false,
            close_to_tray: true,
            log_level: default_log_level(),
        }
    }
}

impl Config {
    pub fn project_dirs() -> Option<ProjectDirs> {
        ProjectDirs::from("systems", "astrea", "axiom-proxy")
    }

    pub fn default_path() -> Result<PathBuf> {
        let dirs = Self::project_dirs()
            .ok_or_else(|| CoreError::Config("no home directory for config path".into()))?;
        Ok(dirs.config_dir().join("config.json"))
    }

    /// Metadata-only request history shared by the desktop and headless proxy variants.
    pub fn history_path() -> Result<PathBuf> {
        let dirs = Self::project_dirs()
            .ok_or_else(|| CoreError::Config("no home directory for history path".into()))?;
        Ok(dirs.data_local_dir().join("request-history.json"))
    }

    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text).map_err(|e| CoreError::Config(e.to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(CoreError::Config(e.to_string())),
        }
    }

    /// Replace the development backend shipped by pre-release desktop builds.
    pub fn migrate_legacy_defaults(&mut self) -> bool {
        if self.schema_version >= CURRENT_CONFIG_VERSION {
            return false;
        }

        if self.backend_url == LEGACY_DEVELOPMENT_BACKEND_URL {
            self.backend_url = default_backend_url();
        }
        self.schema_version = CURRENT_CONFIG_VERSION;
        true
    }

    /// Atomic save: write a temp file next to the target, then rename over it.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| CoreError::Config(e.to_string()))?;
        }
        let tmp = path.with_extension("json.tmp");
        let text =
            serde_json::to_string_pretty(self).map_err(|e| CoreError::Config(e.to_string()))?;
        std::fs::write(&tmp, text).map_err(|e| CoreError::Config(e.to_string()))?;
        std::fs::rename(&tmp, path).map_err(|e| CoreError::Config(e.to_string()))?;
        Ok(())
    }

    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}/v1", self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn production_backend_defaults_to_live_api_domain() {
        assert_eq!(Config::default().backend_url, "https://api.axiom.stream");
    }

    #[test]
    fn migrates_the_pre_release_development_backend() {
        let mut config = Config {
            schema_version: 0,
            backend_url: "http://127.0.0.1:8080".into(),
            ..Config::default()
        };

        assert!(config.migrate_legacy_defaults());
        assert_eq!(config.backend_url, "https://api.axiom.stream");
        assert!(!config.migrate_legacy_defaults());
    }

    #[test]
    fn preserves_an_explicit_local_backend_after_migration() {
        let mut config = Config {
            backend_url: "http://127.0.0.1:8080".into(),
            ..Config::default()
        };

        assert!(!config.migrate_legacy_defaults());
        assert_eq!(config.backend_url, "http://127.0.0.1:8080");
    }
}
