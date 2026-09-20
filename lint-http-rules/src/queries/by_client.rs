// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Query history for one client, across every origin it reached.
//!
//! The widest of the four, and the only one that can answer a question about
//! **two origins**. Two rules ask one: a cookie sent to a host the cookie's
//! `Domain` does not permit is a comparison between the host that set it and
//! the host that received it (RFC 6265 §5.1.3), and an OAuth 2.0 authorization
//! code flow sends §4.1.1's request to the identity provider and receives
//! §4.1.2's callback at the client's own domain. Neither pair of messages is
//! ever in one origin's history, so both rules read a history that could not
//! contain what they correlate against — and the entries behind that
//! correlation fired on no value at all.
//!
//! **The client is the bound, and it is the subject's own.** RFC 6265 §5.3
//! stores cookies in a user agent's store, and the `state` parameter binds a
//! callback to a request the same user agent made; a history wider than one
//! client would correlate one person's flow against another's, which is not a
//! wider reading of the same sentence but a different sentence. `ByResourceAll`
//! is the one query that drops the client, and it does so for a rule whose
//! whole question is what a *second* client was handed.

use crate::state::{ClientIdentifier, StateStore};
use crate::transaction_history::TransactionHistory;

/// Return every transaction this client made, newest-first by timestamp.
pub fn by_client(state: &StateStore, client: &ClientIdentifier) -> TransactionHistory {
    let mut txs = state.collect_for_client(client);
    txs.sort_by_key(|tx| std::cmp::Reverse(tx.timestamp));
    TransactionHistory::new(txs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_client() -> ClientIdentifier {
        ClientIdentifier::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), "ua".to_string())
    }

    /// The property `by_origin` does not have, stated as a test: two origins,
    /// one client, both in the history.
    #[test]
    fn spans_two_origins_for_one_client() {
        let store = StateStore::new(300, 10);
        let client = make_client();
        for uri in [
            "https://idp.example.com/authorize",
            "https://app.example.net/callback",
        ] {
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            tx.client = client.clone();
            tx.request.uri = uri.to_string();
            store.record_transaction(&tx);
        }
        assert_eq!(by_client(&store, &client).len(), 2);
    }

    /// And the bound: another client's traffic is not in it.
    #[test]
    fn another_client_is_not_in_it() {
        let store = StateStore::new(300, 10);
        let mine = make_client();
        let theirs = ClientIdentifier::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), "ua".into());
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = theirs;
        tx.request.uri = "https://example.com/x".into();
        store.record_transaction(&tx);
        assert!(by_client(&store, &mine).is_empty());
    }
}
