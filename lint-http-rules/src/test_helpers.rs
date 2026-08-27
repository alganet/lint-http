// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Test utilities for the rules crate.
//!
//! Re-exports the core fixtures (built on core types) and adds rule-layer
//! fixtures that need types defined here. Rule modules reach these through
//! `crate::test_helpers::…`.

pub use lint_http_core::test_helpers::*;

/// Prepare `rule` under `cfg`, then dispatch one transaction through it — the
/// way the engine does, collapsed to one call for tests.
///
/// Returns the **first** finding, which for every single-finding rule is the
/// finding; tests of the multi-finding rules read [`run_rule_all`] instead.
/// Returns `None` when `prepare` rejects the config, which preserves what a
/// failed per-dispatch parse used to answer. Tests asserting *why*
/// preparation fails call `prepare` directly.
pub fn run_rule(
    rule: &dyn crate::rules::Rule,
    tx: &crate::http_transaction::HttpTransaction,
    history: &crate::transaction_history::TransactionHistory,
    cfg: &crate::config::Config,
) -> Option<crate::lint::Violation> {
    run_rule_all(rule, tx, history, cfg).into_iter().next()
}

/// Prepare `rule` under `cfg`, then dispatch one transaction and return every
/// finding. An unpreparable config yields the empty vector.
pub fn run_rule_all(
    rule: &dyn crate::rules::Rule,
    tx: &crate::http_transaction::HttpTransaction,
    history: &crate::transaction_history::TransactionHistory,
    cfg: &crate::config::Config,
) -> Vec<crate::lint::Violation> {
    let Ok(resolved) = rule.prepare(cfg) else {
        return Vec::new();
    };
    rule.findings(tx, history, &crate::rules::RuleContext::new(&resolved))
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
    rule.findings(event, history, &crate::rules::RuleContext::new(&resolved))
        .into_iter()
        .next()
}
