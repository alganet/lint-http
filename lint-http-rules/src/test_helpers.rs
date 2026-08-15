// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Test utilities for the rules crate.
//!
//! Re-exports the core fixtures (built on core types) and adds rule-layer
//! fixtures that need types defined here. Rule modules reach these through
//! `crate::test_helpers::…`.

pub use lint_http_core::test_helpers::*;

/// Create a test rule configuration with `severity: Warn`.
///
/// It set an `enabled: true` beside the severity until the field went: whether a
/// rule runs is `PreparedEngine`'s answer and never the rule's, so a value of
/// this type says only how loud the finding is.
pub fn make_test_rule_config() -> crate::rules::RuleConfig {
    crate::rules::RuleConfig {
        severity: crate::lint::Severity::Warn,
    }
}
