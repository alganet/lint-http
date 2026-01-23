// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Helper utilities shared across multiple lint rules.
//!
//! This module groups reusable helpers for validating HTTP common structures.

pub mod auth;
pub mod content_range;
pub mod domain;
pub mod headers;
pub mod ipv6;
pub mod language;
pub mod token;
pub mod uri;
