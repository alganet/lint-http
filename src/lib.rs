// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! HTTP forward proxy with request/response capture and lint rules.
//!
//! This library provides the core functionality for lint-http, including
//! proxy handling, capture writing, configuration, and lint rule evaluation.

pub mod capture;
pub mod config;
pub mod lint;
pub mod proxy;
pub mod rules;
pub mod state;
pub mod connection;

// Keep library small; main.rs remains the binary entrypoint.
