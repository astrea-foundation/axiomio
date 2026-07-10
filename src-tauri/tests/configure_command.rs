use std::fs;

use assert_cmd::Command;

#[test]
fn command_updates_an_explicit_jsonc_file() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("opencode.jsonc");
    fs::write(
        &config,
        "{\n  // integration comment\n  \"theme\": \"system\",\n}\n",
    )
    .unwrap();

    Command::cargo_bin("axiomio")
        .unwrap()
        .args([
            "configure",
            "opencode",
            "--config",
            config.to_str().unwrap(),
        ])
        .assert()
        .success();

    let updated = fs::read_to_string(&config).unwrap();
    assert!(updated.contains("// integration comment"));
    assert!(updated.contains(r#""reasoning": true"#));
    assert!(updated.contains(r#""tool_call": true"#));
    assert!(updated.contains(r#""max""#));
    assert!(updated.contains(r#""disabled": true"#));
    assert!(updated.contains("@ai-sdk/openai-compatible"));
    assert!(!updated.contains("axm_"));
    assert_eq!(
        fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".bak-"))
            .count(),
        1
    );
}
