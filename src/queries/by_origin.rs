// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Query history for all resources under the same origin.
//!
//! An **origin** is `scheme + host + port` (RFC 6454).  This query collects
//! all transactions for a client whose request URI matches the given origin,
//! regardless of path.  Useful for authentication flows, cookie lifecycle,
//! and cache coherence across paths.

use crate::state::{ClientIdentifier, StateStore};
use crate::transaction_history::TransactionHistory;

/// Return all transactions for `client` whose request URI starts with `origin`.
///
/// `origin` should be in the form `"https://example.com"` or
/// `"http://example.com:8080"` (no trailing slash).
///
/// Results are collected across all resources and sorted newest-first by
/// timestamp.
pub fn by_origin(
    state: &StateStore,
    client: &ClientIdentifier,
    origin: &str,
) -> TransactionHistory {
    let prefix = if origin.ends_with('/') {
        origin.to_string()
    } else {
        format!("{}/", origin)
    };

    let mut txs: Vec<_> = state
        .collect_for_client(client)
        .into_iter()
        .filter(|tx| tx.request.uri.starts_with(&prefix) || tx.request.uri == origin)
        .collect();

    // Sort newest-first by timestamp
    txs.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    TransactionHistory::new(txs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ClientIdentifier;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_client() -> ClientIdentifier {
        ClientIdentifier::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            "test-agent".to_string(),
        )
    }

    #[test]
    fn by_origin_matches_same_origin_different_paths() {
        let store = StateStore::new(300, 10);
        let client = make_client();

        let mut tx1 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx1.client = client.clone();
        tx1.request.uri = "https://example.com/a".to_string();
        store.record_transaction(&tx1);

        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx2.client = client.clone();
        tx2.request.uri = "https://example.com/b".to_string();
        store.record_transaction(&tx2);

        let history = by_origin(&store, &client, "https://example.com");
        assert_eq!(history.len(), 2);
    }

    #[test]
    fn by_origin_excludes_different_origin() {
        let store = StateStore::new(300, 10);
        let client = make_client();

        let mut tx1 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx1.client = client.clone();
        tx1.request.uri = "https://example.com/a".to_string();
        store.record_transaction(&tx1);

        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx2.client = client.clone();
        tx2.request.uri = "https://other.com/a".to_string();
        store.record_transaction(&tx2);

        let history = by_origin(&store, &client, "https://example.com");
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn by_origin_empty_when_no_match() {
        let store = StateStore::new(300, 10);
        let client = make_client();

        let history = by_origin(&store, &client, "https://no-match.com");
        assert!(history.is_empty());
    }

    #[test]
    fn by_origin_does_not_cross_clients() {
        let store = StateStore::new(300, 10);
        let client1 = make_client();
        let client2 = ClientIdentifier::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            "other-agent".to_string(),
        );

        let mut tx1 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx1.client = client1.clone();
        tx1.request.uri = "https://example.com/a".to_string();
        store.record_transaction(&tx1);

        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(201, &[]);
        tx2.client = client2.clone();
        tx2.request.uri = "https://example.com/b".to_string();
        store.record_transaction(&tx2);

        let h1 = by_origin(&store, &client1, "https://example.com");
        assert_eq!(h1.len(), 1);
        assert_eq!(
            h1.previous().unwrap().response.as_ref().unwrap().status,
            200
        );
    }
}
