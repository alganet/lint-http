// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! HTTP forward proxy with request/response capture and lint rules.
//!
//! `lint-http` is a library and CLI tool for intercepting, analyzing, and logging HTTP traffic.
//! It acts as a man-in-the-middle proxy, capable of decrypting HTTPS traffic (via dynamic
//! certificate generation) to inspect headers and payloads for best practice violations.
//!
//! This crate owns the transport, capture, and CA layers and the `lint-http`
//! binary. The data types live in [`lint_http_core`] and the rule catalogue +
//! dispatch engine in [`lint_http_rules`]; both are re-exported here under
//! their original module names so the public `lint_http::…` surface (and
//! intra-crate `crate::…` paths) are unchanged from before the workspace split.

// Core data types.
pub use lint_http_core::{
    config, http_date, http_transaction, lint, protocol_event, protocol_event_store, serde_helpers,
    state, transaction_history,
};

// Rule catalogue, helpers, query layer, and lint dispatch.
pub use lint_http_rules::{engine, gendocs, helpers, lint_protocol, queries, rules};

// Transport / capture / CA layers owned by this crate.
pub mod ca;
pub mod capture;
pub mod connection;
pub mod h3_instrument;
pub mod proxy;
pub mod websocket_session;

#[cfg(test)]
mod test_helpers;

pub fn make_temp_captures_path(prefix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("{}_{}.jsonl", prefix, uuid::Uuid::new_v4()))
}

pub fn make_temp_config_path(prefix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("{}_{}.toml", prefix, uuid::Uuid::new_v4()))
}

#[cfg(test)]
#[test]
fn make_temp_paths_include_prefix() {
    let p = make_temp_captures_path("testprefix");
    assert!(p
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("testprefix"));
    let p2 = make_temp_config_path("cfgprefix");
    assert!(p2
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("cfgprefix"));
}
