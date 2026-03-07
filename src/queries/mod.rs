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
pub mod mapping;
