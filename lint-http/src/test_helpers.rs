// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Test utilities for the proxy crate.
//!
//! Re-exports the core fixtures (built on core types). The proxy's tests only
//! need transaction/config fixtures, not the rule-layer ones.

pub use lint_http_core::test_helpers::*;

/// Proxy-shaped counterpart of `make_test_config_with_enabled_rules`: the
/// same rule table under default transport sections, for fixtures that feed
/// `Shared`/`run_proxy` rather than the rule layer directly.
pub fn make_proxy_config_with_enabled_rules(rules: &[&str]) -> crate::config::Config {
    crate::config::Config {
        lint: lint_http_core::test_helpers::make_test_config_with_enabled_rules(rules),
        ..Default::default()
    }
}
