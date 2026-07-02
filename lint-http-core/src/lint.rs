// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Lint result types.
//!
//! The dispatch engine that produces these from a transaction lives in
//! [`engine`](crate::engine), which sits above the rule catalogue; these data
//! types sit below it (every rule returns a [`Violation`]).

use serde::{Deserialize, Serialize};

/// Represents a single rule violation detected by the linter.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Violation {
    pub rule: String,
    pub severity: Severity,
    pub message: String,
}

/// Severity level for a rule violation. Ordered by increasing severity
/// (`Info < Warn < Error`) so callers can gate on a minimum level.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Error,
}
