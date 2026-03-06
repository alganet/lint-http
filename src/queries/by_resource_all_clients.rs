// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Query history for a specific resource across *all* clients.
//!
//! This is used by rules that need to observe cross-client cache behaviour,
//! such as ensuring `Cache-Control: private` responses are not reused by
//! different clients (shared caches).

use crate::state::StateStore;
use crate::transaction_history::TransactionHistory;

/// Return the bounded history for a given resource regardless of client,
/// newest first.
pub fn by_resource_all_clients(state: &StateStore, resource: &str) -> TransactionHistory {
    TransactionHistory::new(state.get_history_for_resource(resource))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ClientIdentifier;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_client(ip: [u8; 4], ua: &str) -> ClientIdentifier {
        ClientIdentifier::new(
            IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
            ua.to_string(),
        )
    }

    #[test]
    fn returns_history_across_clients() {
        let store = crate::state::StateStore::new(300, 10);
        let c1 = make_client([127, 0, 0, 1], "one");
        let c2 = make_client([127, 0, 0, 2], "two");
        let resource = "http://example.com/x";

        let mut tx1 =
            crate::test_helpers::make_test_transaction_with_response(200, &[("etag", "\"a\"")]);
        tx1.client = c1.clone();
        tx1.request.uri = resource.to_string();
        store.record_transaction(&tx1);

        let mut tx2 =
            crate::test_helpers::make_test_transaction_with_response(200, &[("etag", "\"b\"")]);
        tx2.client = c2.clone();
        tx2.request.uri = resource.to_string();
        store.record_transaction(&tx2);

        let history = by_resource_all_clients(&store, resource);
        assert_eq!(history.len(), 2);
        assert!(
            history.previous().unwrap().client == c2 || history.previous().unwrap().client == c1
        );
    }

    #[test]
    fn empty_when_no_match() {
        let store = crate::state::StateStore::new(300, 10);
        let history = by_resource_all_clients(&store, "http://nomatch/1");
        assert!(history.is_empty());
    }
}
