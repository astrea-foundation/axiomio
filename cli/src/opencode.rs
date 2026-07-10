use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use jsonc_parser::cst::CstRootNode;
use jsonc_parser::{json, ParseOptions};
use tempfile::NamedTempFile;

const DEFAULT_CONFIG_FILE: &str = "opencode.json";

pub struct ConfigureOptions {
    pub config_path: Option<PathBuf>,
    pub base_url: String,
    pub dry_run: bool,
}

pub struct ConfigureOutcome {
    pub path: PathBuf,
    pub backup_path: Option<PathBuf>,
    pub rendered: String,
    pub changed: bool,
}

pub fn configure(options: ConfigureOptions) -> Result<ConfigureOutcome> {
    validate_base_url(&options.base_url)?;
    let path = match options.config_path {
        Some(path) => path,
        None => discover_config_path()?,
    };
    let original = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "{}\n".to_string(),
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    let rendered = merge_provider(&original, &options.base_url)?;
    let changed = original != rendered;

    if options.dry_run || !changed {
        return Ok(ConfigureOutcome {
            path,
            backup_path: None,
            rendered,
            changed,
        });
    }

    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("config path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;

    let backup_path = if path.exists() {
        let backup = backup_path(&path)?;
        fs::copy(&path, &backup)
            .with_context(|| format!("back up {} to {}", path.display(), backup.display()))?;
        Some(backup)
    } else {
        None
    };
    write_atomic(&path, rendered.as_bytes())?;

    Ok(ConfigureOutcome {
        path,
        backup_path,
        rendered,
        changed,
    })
}

fn validate_base_url(value: &str) -> Result<()> {
    if !(value.starts_with("http://127.0.0.1:") || value.starts_with("http://localhost:")) {
        bail!("OpenCode base URL must point to the local Axiom proxy");
    }
    if !value.trim_end_matches('/').ends_with("/v1") {
        bail!("OpenCode base URL must end with /v1");
    }
    Ok(())
}

fn discover_config_path() -> Result<PathBuf> {
    let output = Command::new("opencode")
        .args(["debug", "paths"])
        .output()
        .context("run `opencode debug paths`")?;
    if !output.status.success() {
        bail!("`opencode debug paths` failed with {}", output.status);
    }
    let stdout = String::from_utf8(output.stdout).context("OpenCode paths output was not UTF-8")?;
    let config_dir = stdout
        .lines()
        .find_map(|line| {
            let (label, path) = line.split_once(char::is_whitespace)?;
            (label == "config").then(|| PathBuf::from(path.trim()))
        })
        .ok_or_else(|| anyhow!("OpenCode did not report its config directory"))?;
    choose_config_file(&config_dir)
}

fn choose_config_file(config_dir: &Path) -> Result<PathBuf> {
    let json = config_dir.join("opencode.json");
    let jsonc = config_dir.join("opencode.jsonc");
    match (json.exists(), jsonc.exists()) {
        (true, true) => bail!(
            "both {} and {} exist; pass --config to choose explicitly",
            json.display(),
            jsonc.display()
        ),
        (false, true) => Ok(jsonc),
        _ => Ok(config_dir.join(DEFAULT_CONFIG_FILE)),
    }
}

fn merge_provider(source: &str, base_url: &str) -> Result<String> {
    let root = CstRootNode::parse(source, &ParseOptions::default())
        .map_err(|error| anyhow!("invalid OpenCode JSON/JSONC: {error}"))?;
    let object = root.object_value_or_set();
    let providers = object.object_value_or_set("provider");
    let managed_provider = json!({
        "npm": "@ai-sdk/openai-compatible",
        "name": "Axiom",
        "options": {
            "baseURL": base_url,
            "apiKey": "unused"
        },
        "models": {
            "glm-5-2": {
                "name": "Axiom GLM-5.2",
                "reasoning": true,
                "tool_call": true,
                "variants": {
                    "max": { "disabled": true },
                    "low": { "reasoningEffort": "low" },
                    "medium": { "reasoningEffort": "medium" },
                    "high": { "reasoningEffort": "high" },
                    "xhigh": { "reasoningEffort": "xhigh" }
                }
            }
        }
    });
    if let Some(existing) = providers.get("axiom") {
        existing.set_value(managed_provider);
    } else {
        providers.append("axiom", managed_provider);
    }
    let mut rendered = root.to_string();
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    Ok(rendered)
}

fn backup_path(path: &Path) -> Result<PathBuf> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis();
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("config filename is not valid UTF-8"))?;
    for suffix in 0_u32.. {
        let suffix = if suffix == 0 {
            String::new()
        } else {
            format!("-{suffix}")
        };
        let candidate = path.with_file_name(format!("{name}.bak-{timestamp}{suffix}"));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    unreachable!("backup suffix space exhausted")
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("config path has no parent: {}", path.display()))?;
    let mut temp = NamedTempFile::new_in(parent)
        .with_context(|| format!("create temporary file in {}", parent.display()))?;
    temp.write_all(bytes)
        .with_context(|| format!("write temporary config for {}", path.display()))?;
    temp.as_file()
        .sync_all()
        .with_context(|| format!("sync temporary config for {}", path.display()))?;
    temp.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("replace {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_provider_without_changing_other_values_or_comments() {
        let source = r#"{
  // keep this comment
  "theme": "system",
  "provider": {
    "other": { "name": "Other" },
  },
}
"#;
        let output = merge_provider(source, "http://127.0.0.1:8484/v1").unwrap();
        assert!(output.contains("// keep this comment"));
        assert!(output.contains(r#""theme": "system""#));
        assert!(output.contains(r#""other": { "name": "Other" }"#));
        assert!(output.contains(r#""npm": "@ai-sdk/openai-compatible""#));
        assert!(!output.contains("axm_"));
    }

    #[test]
    fn replacing_provider_is_idempotent() {
        let legacy = r#"{
  "provider": {
    "axiom": {
      "name": "AxiomIO",
      "models": {
        "glm-5": { "name": "GLM-5" },
        "glm-5-1": { "name": "GLM-5.1" }
      }
    }
  }
}
"#;
        let once = merge_provider(legacy, "http://127.0.0.1:8484/v1").unwrap();
        let twice = merge_provider(&once, "http://127.0.0.1:8484/v1").unwrap();
        assert_eq!(once, twice);
        assert_eq!(twice.matches(r#""axiom""#).count(), 1);
        assert!(twice.contains(r#""reasoning": true"#));
        assert!(twice.contains(r#""tool_call": true"#));
        assert!(twice.contains(r#""max""#));
        assert!(twice.contains(r#""disabled": true"#));
        assert!(!twice.contains(r#""glm-5-1""#));
        assert!(!twice.contains(r#""glm-5""#));
        for effort in ["low", "medium", "high", "xhigh"] {
            assert!(twice.contains(&format!(r#""reasoningEffort": "{effort}""#)));
        }
        assert_eq!(twice.matches(r#""reasoningEffort""#).count(), 4);
    }

    #[test]
    fn rejects_malformed_config_and_remote_url() {
        assert!(merge_provider("{ nope", "http://127.0.0.1:8484/v1").is_err());
        assert!(validate_base_url("https://api.axiom.stream/v1").is_err());
        assert!(validate_base_url("http://127.0.0.1:8484").is_err());
    }

    #[test]
    fn chooses_existing_format_and_rejects_ambiguous_files() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            choose_config_file(dir.path()).unwrap(),
            dir.path().join("opencode.json")
        );
        fs::write(dir.path().join("opencode.jsonc"), "{}").unwrap();
        assert_eq!(
            choose_config_file(dir.path()).unwrap(),
            dir.path().join("opencode.jsonc")
        );
        fs::write(dir.path().join("opencode.json"), "{}").unwrap();
        assert!(choose_config_file(dir.path()).is_err());
    }

    #[test]
    fn configure_writes_backup_and_skips_unchanged_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opencode.jsonc");
        fs::write(&path, "{\n  // original\n}\n").unwrap();
        let first = configure(ConfigureOptions {
            config_path: Some(path.clone()),
            base_url: "http://127.0.0.1:8484/v1".into(),
            dry_run: false,
        })
        .unwrap();
        assert!(first.changed);
        let backup = first.backup_path.unwrap();
        assert!(backup.exists());
        assert_eq!(fs::read_to_string(backup).unwrap(), "{\n  // original\n}\n");

        let second = configure(ConfigureOptions {
            config_path: Some(path),
            base_url: "http://127.0.0.1:8484/v1".into(),
            dry_run: false,
        })
        .unwrap();
        assert!(!second.changed);
        assert!(second.backup_path.is_none());
    }

    #[test]
    fn dry_run_does_not_create_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opencode.json");
        let result = configure(ConfigureOptions {
            config_path: Some(path.clone()),
            base_url: "http://localhost:8484/v1".into(),
            dry_run: true,
        })
        .unwrap();
        assert!(result.changed);
        assert!(!path.exists());
    }
}
