// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Core data types for `lint-http`.
//!
//! This crate holds everything the rule library and proxy build on but that
//! carries no rule or transport knowledge: the [`HttpTransaction`] model and
//! its [`TransactionHistory`] view, the [`ProtocolEvent`] model and its store,
//! the bounded [`StateStore`], capture (de)serialization helpers, and the
//! [`Config`] loader plus the [`Violation`]/[`Severity`] result types.
//!
//! It depends on no other workspace crate, so it can be reused outside the
//! proxy (HAR/PCAP analyzers, CI fixture linting, replay harnesses).
//!
//! [`HttpTransaction`]: http_transaction::HttpTransaction
//! [`TransactionHistory`]: transaction_history::TransactionHistory
//! [`ProtocolEvent`]: protocol_event::ProtocolEvent
//! [`StateStore`]: state::StateStore
//! [`Config`]: config::Config
//! [`Violation`]: lint::Violation
//! [`Severity`]: lint::Severity

pub mod config;
pub mod http_date;
pub mod http_transaction;
pub mod lint;
pub mod protocol_event;
pub mod protocol_event_store;
pub mod serde_helpers;
pub mod state;
pub mod transaction_history;

// Shared test fixtures. Compiled for this crate's own tests and, via the
// `test-utils` feature, for downstream crates' tests (see each crate's
// dev-dependency on lint-http-core).
#[cfg(any(test, feature = "test-utils"))]
pub mod test_helpers;
