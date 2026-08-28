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
    http_date, http_transaction, lint, protocol_event, protocol_event_store, serde_helpers, state,
    transaction_history,
};

// Rule catalogue, helpers, query layer, and lint dispatch.
pub use lint_http_rules::{engine, helpers, lint_protocol, queries, rules};

// Transport / capture / CA layers owned by this crate. `config` moved here
// from core when the transport surface (`[general]`/`[tls]`) was split away
// from the rule table; the module path is unchanged for both `lint_http::…`
// and `crate::…` users.
// The temp-file guard the tests use, unit and integration alike. Rust gives a
// unit test and an integration test no module in common — one is compiled into
// this library, the other into its own binary — so the file is included from
// where it lives, next to the integration tests that were its first callers. A
// second copy would be the shape this whole pass exists to remove.
#[cfg(test)]
#[path = "../tests/common/temp_files.rs"]
pub(crate) mod temp_files;

pub mod ca;
pub mod capture;
pub mod config;
pub mod connection;
pub mod h3_instrument;
pub mod proxy;
pub mod websocket_session;

#[cfg(test)]
mod test_helpers;
