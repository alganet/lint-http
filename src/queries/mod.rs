// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Reusable state queries for the linting engine.
//!
//! Each query function reads from `StateStore` and returns a
//! `TransactionHistory` that can be passed to rules.  Rules never interact
//! with `StateStore` directly — this module is the bridge.

pub mod by_connection;
pub mod by_origin;
pub mod by_resource;
pub mod by_resource_all_clients;

/// The kind of state query a rule needs to build its `TransactionHistory`.
///
/// The engine consults [`crate::rules::query_type_for`] to decide which query
/// to run for a given rule. This type is deliberately kept off the `Rule`
/// trait: the vast majority of rules read no history at all, and the rule
/// library stays portable by not leaking the engine's query layer into its
/// public trait surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
    ByResource,
    ByOrigin,
    /// Like `ByResource` but returns history for **all clients** that have
    /// accessed the given resource.  Used by rules that need to observe
    /// cross-client behaviour (e.g. private cache visibility).
    ByResourceAll,
    /// Returns all transactions on the same TCP connection, ordered
    /// newest-first by timestamp.  Used by rules that validate
    /// connection-level protocol behaviour (pipelining, multiplexing,
    /// connection reuse).
    ByConnection,
}
