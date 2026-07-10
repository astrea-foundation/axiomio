use std::time::Duration;

use semver::Version;
use serde::{Deserialize, Serialize};

const LATEST_RELEASE_URL: &str =
    "https://api.github.com/repos/astrea-foundation/axiomio/releases/latest";
const MAX_RELEASE_RESPONSE_BYTES: u64 = 512 * 1024;

#[derive(Debug, Deserialize)]
struct LatestRelease {
    tag_name: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    current_version: String,
    latest_version: String,
    available: bool,
    command: String,
}

fn parse_version(value: &str) -> Result<Version, String> {
    Version::parse(value.trim().trim_start_matches('v'))
        .map_err(|error| format!("invalid release version {value:?}: {error}"))
}

fn update_command() -> &'static str {
    if cfg!(windows) {
        "irm https://axiom.stream/axiomup.ps1 | iex"
    } else {
        "curl -fsSL https://axiom.stream/axiomup.sh | bash"
    }
}

fn info_from_tag(current: &str, latest_tag: &str) -> Result<UpdateInfo, String> {
    let current_version = parse_version(current)?;
    let latest_version = parse_version(latest_tag)?;
    Ok(UpdateInfo {
        current_version: current_version.to_string(),
        latest_version: latest_version.to_string(),
        available: latest_version > current_version,
        command: update_command().to_string(),
    })
}

fn info_from_response(current: &str, body: &[u8]) -> Result<UpdateInfo, String> {
    let release: LatestRelease = serde_json::from_slice(body).map_err(|error| error.to_string())?;
    info_from_tag(current, &release.tag_name)
}

#[tauri::command]
pub async fn check_for_update() -> Result<UpdateInfo, String> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(6))
        .user_agent(concat!("axiomio/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| error.to_string())?;
    let mut response = client
        .get(LATEST_RELEASE_URL)
        .header("accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|error| error.to_string())?
        .error_for_status()
        .map_err(|error| error.to_string())?;

    if response
        .content_length()
        .is_some_and(|length| length > MAX_RELEASE_RESPONSE_BYTES)
    {
        return Err("latest release response is too large".to_string());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| error.to_string())? {
        if body.len() as u64 + chunk.len() as u64 > MAX_RELEASE_RESPONSE_BYTES {
            return Err("latest release response is too large".to_string());
        }
        body.extend_from_slice(&chunk);
    }
    info_from_response(env!("CARGO_PKG_VERSION"), &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newer_stable_version_is_available() {
        let info = info_from_tag("0.1.0", "v0.2.0").unwrap();
        assert!(info.available);
        assert_eq!(info.current_version, "0.1.0");
        assert_eq!(info.latest_version, "0.2.0");
        assert!(info.command.contains("axiomup."));
    }

    #[test]
    fn equal_and_older_versions_are_not_available() {
        assert!(!info_from_tag("0.2.0", "v0.2.0").unwrap().available);
        assert!(!info_from_tag("0.3.0", "v0.2.0").unwrap().available);
    }

    #[test]
    fn semver_prerelease_ordering_is_preserved() {
        assert!(info_from_tag("1.0.0-beta.1", "v1.0.0").unwrap().available);
    }

    #[test]
    fn malformed_release_tag_is_rejected() {
        assert!(info_from_tag("0.1.0", "latest").is_err());
    }

    #[test]
    fn latest_release_response_uses_tag_name() {
        let info = info_from_response("0.1.0", br#"{"tag_name":"v0.1.1"}"#).unwrap();
        assert_eq!(info.latest_version, "0.1.1");
        assert!(info.available);
        assert!(info_from_response("0.1.0", br#"{"name":"v0.1.1"}"#).is_err());
    }

    #[test]
    fn command_matches_the_current_platform() {
        if cfg!(windows) {
            assert_eq!(
                update_command(),
                "irm https://axiom.stream/axiomup.ps1 | iex"
            );
        } else {
            assert_eq!(
                update_command(),
                "curl -fsSL https://axiom.stream/axiomup.sh | bash"
            );
        }
    }
}
