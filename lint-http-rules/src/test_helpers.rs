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

/// Dispatch one transaction through `rule` under `cfg`, the way a test would
/// have called `check_transaction` directly.
///
/// Today this is that direct call. When the trait's check signature moves to
/// a prepared [`crate::rules::RuleContext`], this body becomes
/// prepare-then-dispatch — like [`run_protocol_rule`] below — and no test
/// call site moves again. A config that fails preparation will answer `None`
/// here, which is what a failed per-dispatch parse answers today.
pub fn run_rule(
    rule: &dyn crate::rules::Rule,
    tx: &crate::http_transaction::HttpTransaction,
    history: &crate::transaction_history::TransactionHistory,
    cfg: &crate::config::Config,
) -> Option<crate::lint::Violation> {
    rule.check_transaction(tx, history, cfg)
}

/// Prepare `rule` under `cfg`, then dispatch one event through it — the way
/// the engine does, collapsed to one call for tests.
///
/// Returns `None` when `prepare` rejects the config, which preserves what a
/// direct `check_event` call answered when its own parse failed: the rule
/// yields nothing. Tests asserting *why* preparation fails call `prepare`
/// directly.
pub fn run_protocol_rule(
    rule: &dyn crate::rules::ProtocolRule,
    event: &crate::protocol_event::ProtocolEvent,
    history: &crate::protocol_event::ProtocolEventHistory,
    cfg: &crate::config::Config,
) -> Option<crate::lint::Violation> {
    let resolved = rule.prepare(cfg).ok()?;
    rule.check_event(event, history, &crate::rules::RuleContext::new(&resolved))
}
