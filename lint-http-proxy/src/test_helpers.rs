// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Test utilities for the proxy crate.
//!
//! Re-exports the core fixtures (built on core types). The proxy's tests only
//! need transaction/config fixtures, not the rule-layer ones.

pub use lint_http_core::test_helpers::*;
