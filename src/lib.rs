// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! HTTP forward proxy with request/response capture and lint rules.
//!
//! `lint-http` is a library and CLI tool for intercepting, analyzing, and logging HTTP traffic.
//! It acts as a man-in-the-middle proxy, capable of decrypting HTTPS traffic (via dynamic
//! certificate generation) to inspect headers and payloads for best practice violations.
//!
//! # Core Modules
//!
//! - [`proxy`]: The main HTTP/HTTPS proxy logic.
//! - [`lint`]: The linting engine that evaluates rules against requests and responses.
//! - [`rules`]: Definitions of individual lint rules.
//! - [`ca`]: Certificate Authority for generating dynamic TLS certificates.
//! - [`capture`]: Structured logging of traffic to JSONL files.
//! - [`config`]: Configuration loading and management.
//! - [`state`]: Stateful analysis for tracking behavior across multiple requests.
//!
//! # Usage
//!
//! This library is primarily used by the `lint-http` binary. However, the modules can be
//! used independently for custom proxy or linting applications.

pub mod ca;
pub mod capture;
pub mod config;
pub mod connection;
pub mod helpers;
pub mod http_date;
pub mod http_transaction;
pub mod lint;
pub mod proxy;
pub mod rules;
pub mod serde_helpers;
pub mod state;

#[cfg(test)]
mod test_helpers;
#[cfg(test)]
pub use test_helpers::{
    disable_rule, enable_rule, enable_rule_with_paths, make_headers_from_pairs, make_test_client,
    make_test_config_with_enabled_rules, make_test_engine, make_test_rule_config,
    make_test_transaction, make_test_transaction_with_response,
};

pub fn make_temp_captures_path(prefix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("{}_{}.jsonl", prefix, uuid::Uuid::new_v4()))
}

pub fn make_temp_config_path(prefix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("{}_{}.toml", prefix, uuid::Uuid::new_v4()))
}
