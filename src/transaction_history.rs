// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Simple, rule-friendly transaction history container.
//!
//! This struct is the boundary between the state management engine and the
//! lint rules. Rules depend only on `TransactionHistory` (and `HttpTransaction`),
//! never on `StateStore` or the query layer, so the rule crate can be extracted
//! independently in the future.

use crate::http_transaction::HttpTransaction;

/// Pre-queried transaction history passed to rules.
///
/// Contains zero or more previous transactions for a given query scope,
/// ordered **newest first**.  Rules use the convenience helpers to inspect
/// the history without knowing how it was produced.
#[derive(Debug, Clone)]
pub struct TransactionHistory {
    entries: Vec<HttpTransaction>,
}

impl TransactionHistory {
    /// Create an empty history (no prior transactions observed).
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Create a history from a pre-sorted (newest-first) list of transactions.
    pub fn new(entries: Vec<HttpTransaction>) -> Self {
        Self { entries }
    }

    /// Return the most recent previous transaction, if any.
    ///
    /// This is the direct replacement for the old `previous: Option<&HttpTransaction>`
    /// parameter that rules used to receive.
    pub fn previous(&self) -> Option<&HttpTransaction> {
        self.entries.first()
    }

    /// Iterate over all entries, newest first.
    pub fn iter(&self) -> impl Iterator<Item = &HttpTransaction> {
        self.entries.iter()
    }

    /// Number of entries in the history.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the history is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_history() {
        let h = TransactionHistory::empty();
        assert!(h.is_empty());
        assert_eq!(h.len(), 0);
        assert!(h.previous().is_none());
        assert_eq!(h.iter().count(), 0);
    }

    #[test]
    fn history_with_entries() {
        let tx1 = crate::test_helpers::make_test_transaction();
        let tx2 = crate::test_helpers::make_test_transaction();
        let h = TransactionHistory::new(vec![tx1.clone(), tx2.clone()]);

        assert!(!h.is_empty());
        assert_eq!(h.len(), 2);
        assert!(h.previous().is_some());
        assert_eq!(h.previous().unwrap().id, tx1.id);
        assert_eq!(h.iter().count(), 2);
    }

    #[test]
    fn previous_returns_first_entry() {
        let tx = crate::test_helpers::make_test_transaction();
        let h = TransactionHistory::new(vec![tx.clone()]);
        assert_eq!(h.previous().unwrap().id, tx.id);
    }
}
