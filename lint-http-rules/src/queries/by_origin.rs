// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Query history for all resources under the same origin.
//!
//! An **origin** is `scheme + host + port` (RFC 6454). This query collects all
//! transactions for a client that reached the same one, regardless of path.
//! Useful for authentication flows, cookie lifecycle, and cache coherence
//! across paths.
//!
//! **The origin is reconstructed from each message, not sliced off its
//! request-target.** This was a `starts_with` over the request URI, which only
//! an absolute-form target can satisfy: an origin-form target — the ordinary
//! HTTP/1.1 request, and half the records of an ordinary capture — matched no
//! prefix and could not supply one either, so every by-origin rule was handed
//! an empty history and reported nothing. A stateful rule with no history does
//! not announce that it had none; it reads as a rule that found nothing wrong.
//!
//! [`TargetOrigin`] is the reconstruction and [`TargetOrigin::same_as`] is the
//! comparison, including what it does when one of the two messages does not
//! state a scheme.

use crate::helpers::request_target::TargetOrigin;
use crate::state::{ClientIdentifier, StateStore};
use crate::transaction_history::TransactionHistory;

/// Return all transactions for `client` that reached the same origin as
/// `origin`, newest-first.
///
/// A past transaction whose own message names no host is in no origin and is
/// never returned.
pub fn by_origin(
    state: &StateStore,
    client: &ClientIdentifier,
    origin: &TargetOrigin,
) -> TransactionHistory {
    let mut txs: Vec<_> = state
        .collect_for_client(client)
        .into_iter()
        .filter(|tx| {
            TargetOrigin::of(&tx.request.uri, &tx.request.headers)
                .is_some_and(|past| past.same_as(origin))
        })
        .collect();

    // Sort newest-first by timestamp
    txs.sort_by_key(|tx| std::cmp::Reverse(tx.timestamp));

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

    /// The origin a request in absolute-form reached, with no `Host` needed.
    fn origin_of(uri: &str) -> TargetOrigin {
        TargetOrigin::of(uri, &hyper::HeaderMap::new()).expect("a test origin")
    }

    /// A stored transaction written the way an ordinary HTTP/1.1 client writes
    /// one: an origin-form target and a `Host`.
    fn origin_form_tx(
        client: &ClientIdentifier,
        path: &str,
        host: &str,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = client.clone();
        tx.request.uri = path.to_string();
        tx.request
            .headers
            .insert("host", hyper::header::HeaderValue::from_str(host).unwrap());
        tx
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

        let history = by_origin(&store, &client, &origin_of("https://example.com/"));
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

        let history = by_origin(&store, &client, &origin_of("https://example.com/"));
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn by_origin_empty_when_no_match() {
        let store = StateStore::new(300, 10);
        let client = make_client();

        let history = by_origin(&store, &client, &origin_of("https://no-match.com/"));
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
        tx2.client = client2;
        tx2.request.uri = "https://example.com/b".to_string();
        store.record_transaction(&tx2);

        let h1 = by_origin(&store, &client1, &origin_of("https://example.com/"));
        assert_eq!(h1.len(), 1);
        assert_eq!(
            h1.previous().unwrap().response.as_ref().unwrap().status,
            200
        );
    }
    /// The shape the `starts_with` could not match: an origin-form target and
    /// a `Host`, which is how an HTTP/1.1 client writes a request and how half
    /// the records of an ordinary capture arrive. Both directions — a stored
    /// one found by an absolute-form question, and an absolute-form one found
    /// by an origin-form question.
    #[test]
    fn an_origin_form_request_is_in_an_origin() {
        let store = StateStore::new(300, 10);
        let client = make_client();
        store.record_transaction(&origin_form_tx(&client, "/a", "example.com"));

        let mut absolute = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        absolute.client = client.clone();
        absolute.request.uri = "https://example.com/b".to_string();
        store.record_transaction(&absolute);

        assert_eq!(
            by_origin(&store, &client, &origin_of("https://example.com/")).len(),
            2
        );
        let from_origin_form = TargetOrigin::of(
            "/c",
            &origin_form_tx(&client, "/c", "example.com").request.headers,
        )
        .expect("a host in Host");
        assert_eq!(by_origin(&store, &client, &from_origin_form).len(), 2);
    }

    /// § 5 keeps the two schemes apart where both messages state one.
    #[test]
    fn a_stated_scheme_still_separates_two_origins() {
        let store = StateStore::new(300, 10);
        let client = make_client();
        for uri in ["https://example.com/a", "http://example.com/a"] {
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            tx.client = client.clone();
            tx.request.uri = uri.to_string();
            store.record_transaction(&tx);
        }
        assert_eq!(
            by_origin(&store, &client, &origin_of("https://example.com/")).len(),
            1
        );
        assert_eq!(
            by_origin(&store, &client, &origin_of("http://example.com/")).len(),
            1
        );
        // And the origin-form question, which states neither, reaches both.
        let unstated = TargetOrigin::of(
            "/a",
            &origin_form_tx(&client, "/a", "example.com").request.headers,
        )
        .expect("a host in Host");
        assert_eq!(by_origin(&store, &client, &unstated).len(), 2);
    }

    /// The default port is not part of the authority, so a target that writes
    /// it and one that does not are one origin.
    #[test]
    fn the_default_port_is_elided_from_the_key() {
        let store = StateStore::new(300, 10);
        let client = make_client();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = client.clone();
        tx.request.uri = "https://example.com:443/a".to_string();
        store.record_transaction(&tx);
        assert_eq!(
            by_origin(&store, &client, &origin_of("https://example.com/")).len(),
            1
        );
        // A port that is not the default is a different origin.
        assert_eq!(
            by_origin(&store, &client, &origin_of("https://example.com:8443/")).len(),
            0
        );
    }

    /// A message that names no host is in no origin, and nothing groups with
    /// it. `""` would have grouped every such request together.
    #[test]
    fn a_request_naming_no_host_is_in_no_origin() {
        let store = StateStore::new(300, 10);
        let client = make_client();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.client = client.clone();
        tx.request.uri = "/a".to_string();
        tx.request.headers.remove("host");
        store.record_transaction(&tx);

        assert!(TargetOrigin::of("/a", &tx.request.headers).is_none());
        assert!(by_origin(&store, &client, &origin_of("https://example.com/")).is_empty());
    }
}
