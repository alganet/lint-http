// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Integration tests for the captures_seed feature

use std::sync::Arc;
use tokio::fs;
use uuid::Uuid;

#[tokio::test]
async fn test_captures_seed_enabled() {
    // Create a temporary captures file with sample data
    let tmp_dir = std::env::temp_dir();
    let captures_file = tmp_dir.join(format!("test_seed_{}.jsonl", Uuid::new_v4()));
    let config_file = tmp_dir.join(format!("test_config_{}.toml", Uuid::new_v4()));

    // Write a sample capture record
    let capture_data = r#"{"id":"test-1","timestamp":"2024-01-01T00:00:00Z","method":"GET","uri":"http://example.com/test","status":200,"duration_ms":100,"request_headers":{"user-agent":"test-client"},"response_headers":{"etag":"\"abc123\"","cache-control":"max-age=3600"},"violations":[]}"#;
    fs::write(&captures_file, capture_data)
        .await
        .expect("write captures file");

    // Create a config with captures_seed enabled
    let config_toml = format!(
        r#"[general]
listen = "127.0.0.1:0"
captures = "{}"
ttl_seconds = 300
captures_seed = true

[tls]
enabled = false

[rules]
"#,
        captures_file.to_str().unwrap()
    );
    fs::write(&config_file, config_toml)
        .await
        .expect("write config file");

    // Load the config
    let cfg = lint_http::config::Config::load_from_path(&config_file)
        .await
        .expect("load config");
    let cfg = Arc::new(cfg);

    // Verify config loaded correctly
    assert!(cfg.general.captures_seed);
    assert_eq!(
        cfg.general.captures,
        captures_file.to_str().unwrap().to_string()
    );

    // Create state store and seed it
    let state = Arc::new(lint_http::state::StateStore::new(cfg.general.ttl_seconds));

    // Manually seed from the captures file (simulating what run_proxy does)
    let records = lint_http::capture::load_captures(&cfg.general.captures)
        .await
        .expect("load captures");
    assert_eq!(records.len(), 1);

    for record in &records {
        state.seed_from_capture(record);
    }

    // Verify state was seeded
    let client = lint_http::state::ClientIdentifier::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        "test-client".to_string(),
    );

    let prev = state.get_previous(&client, "http://example.com/test");
    assert!(prev.is_some(), "State should contain seeded transaction");

    let prev = prev.unwrap();
    assert_eq!(prev.status, 200);
    assert_eq!(prev.etag, Some("\"abc123\"".to_string()));
    assert_eq!(prev.cache_control, Some("max-age=3600".to_string()));

    // Cleanup
    let _ = fs::remove_file(&captures_file).await;
    let _ = fs::remove_file(&config_file).await;
}

#[tokio::test]
async fn test_captures_seed_disabled() {
    // Create temporary files
    let tmp_dir = std::env::temp_dir();
    let captures_file = tmp_dir.join(format!("test_seed_disabled_{}.jsonl", Uuid::new_v4()));
    let config_file = tmp_dir.join(format!("test_config_disabled_{}.toml", Uuid::new_v4()));

    // Write a sample capture record
    let capture_data = r#"{"id":"test-2","timestamp":"2024-01-01T00:00:00Z","method":"GET","uri":"http://example.com/test2","status":200,"duration_ms":100,"request_headers":{"user-agent":"test-client-2"},"response_headers":{"etag":"\"xyz789\""},"violations":[]}"#;
    fs::write(&captures_file, capture_data)
        .await
        .expect("write captures file");

    // Create a config with captures_seed disabled (default)
    let config_toml = format!(
        r#"[general]
listen = "127.0.0.1:0"
captures = "{}"
ttl_seconds = 300
captures_seed = false

[tls]
enabled = false

[rules]
"#,
        captures_file.to_str().unwrap()
    );
    fs::write(&config_file, config_toml)
        .await
        .expect("write config file");

    // Load the config
    let cfg = lint_http::config::Config::load_from_path(&config_file)
        .await
        .expect("load config");

    // Verify captures_seed is false
    assert!(!cfg.general.captures_seed);

    // Create state store (without seeding)
    let state = lint_http::state::StateStore::new(cfg.general.ttl_seconds);

    // Verify state is empty (not seeded)
    let client = lint_http::state::ClientIdentifier::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        "test-client-2".to_string(),
    );

    let prev = state.get_previous(&client, "http://example.com/test2");
    assert!(
        prev.is_none(),
        "State should be empty when captures_seed is false"
    );

    // Cleanup
    let _ = fs::remove_file(&captures_file).await;
    let _ = fs::remove_file(&config_file).await;
}

#[tokio::test]
async fn test_captures_seed_with_nonexistent_file() {
    // Create a config pointing to a non-existent captures file
    let tmp_dir = std::env::temp_dir();
    let captures_file = tmp_dir.join(format!("nonexistent_{}.jsonl", Uuid::new_v4()));
    let config_file = tmp_dir.join(format!("test_config_nonexistent_{}.toml", Uuid::new_v4()));

    let config_toml = format!(
        r#"[general]
listen = "127.0.0.1:0"
captures = "{}"
ttl_seconds = 300
captures_seed = true

[tls]
enabled = false

[rules]
"#,
        captures_file.to_str().unwrap()
    );
    fs::write(&config_file, config_toml)
        .await
        .expect("write config file");

    let cfg = lint_http::config::Config::load_from_path(&config_file)
        .await
        .expect("load config");

    // load_captures should return empty vector, not error
    let records = lint_http::capture::load_captures(&cfg.general.captures)
        .await
        .expect("load_captures should succeed even with missing file");

    assert_eq!(
        records.len(),
        0,
        "Should return empty vector for non-existent file"
    );

    // Cleanup
    let _ = fs::remove_file(&config_file).await;
}
