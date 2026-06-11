// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The `lint-http` rule catalogue and lint dispatch.
//!
//! This crate holds the [`Rule`](rules::Rule) catalogue (self-registered via
//! `linkme`), the helper utilities rules build on, the state-query layer, and
//! the dispatch engine ([`engine::lint_transaction`],
//! [`lint_protocol::lint_protocol_event`]). It depends only on
//! [`lint_http_core`].
//!
//! The core data types are re-exported here under their original module names
//! so rule modules can keep referring to `crate::http_transaction::…`,
//! `crate::config::Config`, `crate::lint::Violation`, etc.

pub use lint_http_core::{
    config, http_date, http_transaction, lint, protocol_event, protocol_event_store, serde_helpers,
    state, transaction_history,
};

pub mod engine;
pub mod gendocs;
pub mod helpers;
pub mod lint_protocol;
pub mod queries;
pub mod rules;

#[cfg(test)]
mod test_helpers;
