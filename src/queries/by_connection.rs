// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Query history for all transactions on the same TCP connection.
//!
//! Returns all transactions sharing a `connection_id`, sorted newest-first
//! by timestamp to satisfy the `TransactionHistory` invariant.  Rules that
//! need wire-order analysis should sort by `sequence_number` themselves.

use crate::state::StateStore;
use crate::transaction_history::TransactionHistory;
use uuid::Uuid;

/// Return all transactions recorded on the connection identified by
/// `connection_id`, ordered newest-first by timestamp.
pub fn by_connection(state: &StateStore, connection_id: Uuid) -> TransactionHistory {
    let mut txs = state.get_history_for_connection(connection_id);
    // Sort newest-first by timestamp to satisfy TransactionHistory invariant.
    // Rules can use sequence_number for wire-order analysis.
    txs.sort_by_key(|tx| std::cmp::Reverse(tx.timestamp));
    TransactionHistory::new(txs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{ClientIdentifier, StateStore};
    use std::net::{IpAddr, Ipv4Addr};

    fn make_client() -> ClientIdentifier {
        ClientIdentifier::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            "test-agent".to_string(),
        )
    }

    #[test]
    fn by_connection_returns_transactions_on_same_connection() {
        let store = StateStore::new(300, 10);
        let client = make_client();
        let conn_id = Uuid::new_v4();

        let mut tx1 =
            crate::test_helpers::make_test_transaction_with_response(200, &[("etag", "\"a\"")]);
        tx1.client = client.clone();
        tx1.request.uri = "http://example.com/a".to_string();
        tx1.connection_id = Some(conn_id);
        tx1.sequence_number = Some(0);
        tx1.timestamp = chrono::Utc::now();
        store.record_transaction(&tx1);

        let mut tx2 =
            crate::test_helpers::make_test_transaction_with_response(200, &[("etag", "\"b\"")]);
        tx2.client = client.clone();
        tx2.request.uri = "http://example.com/b".to_string();
        tx2.connection_id = Some(conn_id);
        tx2.sequence_number = Some(1);
        tx2.timestamp = chrono::Utc::now() + chrono::Duration::seconds(1);
        store.record_transaction(&tx2);

        let history = by_connection(&store, conn_id);
        assert_eq!(history.len(), 2);
        // Newest-first: tx2 (sequence 1) should come first
        assert_eq!(history.iter().next().unwrap().sequence_number, Some(1));
    }

    #[test]
    fn by_connection_excludes_other_connections() {
        let store = StateStore::new(300, 10);
        let client = make_client();
        let conn1 = Uuid::new_v4();
        let conn2 = Uuid::new_v4();

        let mut tx1 = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx1.client = client.clone();
        tx1.request.uri = "http://example.com/a".to_string();
        tx1.connection_id = Some(conn1);
        tx1.sequence_number = Some(0);
        store.record_transaction(&tx1);

        let mut tx2 = crate::test_helpers::make_test_transaction_with_response(201, &[]);
        tx2.client = client.clone();
        tx2.request.uri = "http://example.com/b".to_string();
        tx2.connection_id = Some(conn2);
        tx2.sequence_number = Some(0);
        store.record_transaction(&tx2);

        let history = by_connection(&store, conn1);
        assert_eq!(history.len(), 1);
        assert_eq!(
            history
                .previous()
                .unwrap()
                .response
                .as_ref()
                .unwrap()
                .status,
            200
        );
    }

    #[test]
    fn by_connection_empty_when_no_match() {
        let store = StateStore::new(300, 10);
        let history = by_connection(&store, Uuid::new_v4());
        assert!(history.is_empty());
    }
}
