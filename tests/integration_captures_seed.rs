// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Integration tests for the captures_seed feature

use std::sync::Arc;
use tokio::fs;
use uuid::Uuid;

#[tokio::test]
async fn test_captures_seed_enabled() -> anyhow::Result<()> {
    // Create a temporary captures file with sample data
    let tmp_dir = std::env::temp_dir();
    let captures_file = tmp_dir.join(format!("test_seed_{}.jsonl", Uuid::new_v4()));
    let config_file = tmp_dir.join(format!("test_config_{}.toml", Uuid::new_v4()));

    // Construct a minimal transaction record (do not use internal test helpers)
    use lint_http::http_transaction::{HttpTransaction, ResponseInfo, TimingInfo};

    let client = lint_http::state::ClientIdentifier::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        "test-client".to_string(),
    );
    let mut tx = HttpTransaction::new(
        client,
        "GET".to_string(),
        "http://example.com/test".to_string(),
    );
    tx.request
        .headers
        .insert("user-agent", "test-client".parse()?);
    tx.timing = TimingInfo { duration_ms: 100 };

    // Add response headers that seed logic expects
    let mut resp_headers = hyper::HeaderMap::new();
    resp_headers.insert("etag", "\"abc123\"".parse()?);
    resp_headers.insert("cache-control", "max-age=3600".parse()?);
    tx.response = Some(ResponseInfo {
        status: 200,
        headers: resp_headers,
    });

    fs::write(&captures_file, serde_json::to_string(&tx)?).await?;

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
        captures_file
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("captures path not utf8"))?
    );
    fs::write(&config_file, config_toml).await?;

    // Load the config
    let cfg = lint_http::config::Config::load_from_path(&config_file).await?;
    let cfg = Arc::new(cfg);

    // Verify config loaded correctly
    assert!(cfg.general.captures_seed);
    let captures_s = captures_file
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("captures path not utf8"))?
        .to_string();
    assert_eq!(cfg.general.captures, captures_s);

    // Create state store and seed it
    let state = Arc::new(lint_http::state::StateStore::new(cfg.general.ttl_seconds));

    // Manually seed from the captures file (simulating what run_proxy does)
    let records = lint_http::capture::load_captures(&cfg.general.captures).await?;
    assert_eq!(records.len(), 1);

    for record in &records {
        state.seed_from_transaction(record);
    }

    // Verify state was seeded
    let client = lint_http::state::ClientIdentifier::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        "test-client".to_string(),
    );

    let prev = state
        .get_previous(&client, "http://example.com/test")
        .ok_or_else(|| anyhow::anyhow!("State should contain seeded transaction"))?;
    assert_eq!(prev.status, 200);
    assert_eq!(prev.etag, Some("\"abc123\"".to_string()));
    assert_eq!(prev.cache_control, Some("max-age=3600".to_string()));

    // Cleanup
    fs::remove_file(&captures_file).await?;
    fs::remove_file(&config_file).await?;
    Ok(())
}

#[tokio::test]
async fn test_captures_seed_disabled() -> anyhow::Result<()> {
    // Create temporary files
    let tmp_dir = std::env::temp_dir();
    let captures_file = tmp_dir.join(format!("test_seed_disabled_{}.jsonl", Uuid::new_v4()));
    let config_file = tmp_dir.join(format!("test_config_disabled_{}.toml", Uuid::new_v4()));

    // Construct a minimal transaction record without using internal test helpers
    use lint_http::http_transaction::{HttpTransaction, ResponseInfo, TimingInfo};

    let client = lint_http::state::ClientIdentifier::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        "test-client-2".to_string(),
    );
    let mut tx = HttpTransaction::new(
        client,
        "GET".to_string(),
        "http://example.com/test2".to_string(),
    );
    tx.request
        .headers
        .insert("user-agent", "test-client-2".parse()?);
    tx.timing = TimingInfo { duration_ms: 100 };

    // Add a response header for completeness
    let mut resp_headers = hyper::HeaderMap::new();
    resp_headers.insert("etag", "\"xyz789\"".parse()?);
    tx.response = Some(ResponseInfo {
        status: 200,
        headers: resp_headers,
    });

    fs::write(&captures_file, serde_json::to_string(&tx)?).await?;

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
        captures_file
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("captures path not utf8"))?
    );
    fs::write(&config_file, config_toml).await?;

    // Load the config
    let cfg = lint_http::config::Config::load_from_path(&config_file).await?;

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
    fs::remove_file(&captures_file).await?;
    fs::remove_file(&config_file).await?;
    Ok(())
}

#[tokio::test]
async fn test_captures_seed_with_nonexistent_file() -> anyhow::Result<()> {
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
        captures_file
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("captures path not utf8"))?
    );
    fs::write(&config_file, config_toml).await?;

    let cfg = lint_http::config::Config::load_from_path(&config_file).await?;

    // load_captures should return empty vector, not error
    let records = lint_http::capture::load_captures(&cfg.general.captures).await?;

    assert_eq!(
        records.len(),
        0,
        "Should return empty vector for non-existent file"
    );

    // Cleanup
    fs::remove_file(&config_file).await?;
    Ok(())
}
