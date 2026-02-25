// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Integration tests for the captures_seed feature

use lint_http::{make_temp_captures_path, make_temp_config_path};
use rstest::rstest;
use tokio::fs;

#[rstest]
#[case(true)]
#[case(false)]
#[tokio::test]
async fn test_captures_seed_behavior(#[case] seed_enabled: bool) -> anyhow::Result<()> {
    let suffix = if seed_enabled { "enabled" } else { "disabled" };
    let captures_file = make_temp_captures_path(&format!("test_seed_{}", suffix));
    let config_file = make_temp_config_path(&format!("test_config_{}", suffix));

    use lint_http::http_transaction::{HttpTransaction, ResponseInfo, TimingInfo};

    let client = lint_http::state::ClientIdentifier::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        "test-client".to_string(),
    );
    let uri = "http://example.com/test";
    let mut tx = HttpTransaction::new(client.clone(), "GET".to_string(), uri.to_string());
    tx.request
        .headers
        .insert("user-agent", "test-client".parse()?);
    tx.timing = TimingInfo { duration_ms: 100 };

    let mut resp_headers = hyper::HeaderMap::new();
    resp_headers.insert("etag", "\"abc123\"".parse()?);
    tx.response = Some(ResponseInfo {
        status: 200,
        version: "HTTP/1.1".into(),
        headers: resp_headers,

        body_length: None,
    });

    fs::write(&captures_file, serde_json::to_string(&tx)?).await?;

    let config_toml = format!(
        r#"[general]
listen = "127.0.0.1:0"
captures = "{}"
ttl_seconds = 300
captures_seed = {}

[tls]
enabled = false

[rules]
"#,
        captures_file
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("captures path not utf8"))?,
        seed_enabled
    );
    fs::write(&config_file, config_toml).await?;

    let (cfg, _engine) = lint_http::config::Config::load_from_path(&config_file).await?;
    let state = lint_http::state::StateStore::new(cfg.general.ttl_seconds, cfg.general.max_history);

    if cfg.general.captures_seed {
        let records = lint_http::capture::load_captures(&cfg.general.captures).await?;
        for record in &records {
            state.seed_from_transaction(record);
        }
    }

    let prev = state.get_previous(&client, uri);
    if seed_enabled {
        assert!(prev.is_some(), "State should be seeded");
        assert_eq!(prev.unwrap().response.unwrap().status, 200);
    } else {
        assert!(prev.is_none(), "State should not be seeded");
    }

    fs::remove_file(&captures_file).await?;
    fs::remove_file(&config_file).await?;
    Ok(())
}

#[tokio::test]
async fn test_captures_seed_with_nonexistent_file() -> anyhow::Result<()> {
    // Create a config pointing to a non-existent captures file
    let captures_file = make_temp_captures_path("nonexistent");
    let config_file = make_temp_config_path("test_config_nonexistent");

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

    let (cfg, _engine) = lint_http::config::Config::load_from_path(&config_file).await?;

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
