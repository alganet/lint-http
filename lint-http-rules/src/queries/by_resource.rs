// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Query history for an exact client + request URI.
//!
//! This is the most common query dimension — used by conditional-request
//! checks, redirect-chain validation, and cache-validation rules.
//!
//! Both halves of the key are the query's: every entry handed to a rule already
//! has this client and this request target, so a consumer comparing either one
//! against the transaction in hand is writing a test that cannot be false.
//! `stateful_103_early_hints_before_final` compared both, and dropped them when
//! it was audited. `cache_coherence` still compares the URI — that one
//! is left where it is, because deleting it belongs to that rule's own audit
//! along with the approximation its comment describes.

use crate::state::{ClientIdentifier, StateStore};
use crate::transaction_history::TransactionHistory;

/// Return the bounded history for a specific `(client, resource)` pair,
/// newest first.
pub fn by_resource(
    state: &StateStore,
    client: &ClientIdentifier,
    resource: &str,
) -> TransactionHistory {
    TransactionHistory::new(state.get_history(client, resource))
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
    fn by_resource_returns_history() {
        let store = StateStore::new(300, 10);
        let client = make_client();
        let resource = "http://example.com/res";

        let mut tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[("etag", "\"a\"")]);
        tx.client = client.clone();
        tx.request.uri = resource.to_string();
        store.record_transaction(&tx);

        let history = by_resource(&store, &client, resource);
        assert_eq!(history.len(), 1);
        assert!(history.previous().is_some());
    }

    #[test]
    fn by_resource_empty_when_no_match() {
        let store = StateStore::new(300, 10);
        let client = make_client();

        let history = by_resource(&store, &client, "http://example.com/no-match");
        assert!(history.is_empty());
        assert!(history.previous().is_none());
    }
}
