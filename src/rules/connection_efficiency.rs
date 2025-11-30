// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::{ClientIdentifier, StateStore};
use hyper::{HeaderMap, Method};

/// Minimum connection count before checking efficiency to avoid noise during initial load
const MIN_CONNECTIONS_FOR_EFFICIENCY_CHECK: u64 = 5;

/// Expected minimum connection reuse ratio (requests per connection).
/// Values below this indicate poor connection reuse (missing Keep-Alive).
const MIN_EFFICIENT_REUSE_RATIO: f64 = 1.1;

pub struct ConnectionEfficiency;

impl Rule for ConnectionEfficiency {
    fn id(&self) -> &'static str {
        "connection_efficiency"
    }

    fn check_request(
        &self,
        client: &ClientIdentifier,
        _resource: &str,
        _method: &Method,
        _headers: &HeaderMap,
        _conn: &crate::connection::ConnectionMetadata,
        state: &StateStore,
    ) -> Option<Violation> {
        let count = state.get_connection_count(client);

        if count > MIN_CONNECTIONS_FOR_EFFICIENCY_CHECK {
            if let Some(efficiency) = state.get_connection_efficiency(client) {
                // Efficiency = requests / connections.
                // If efficiency is close to 1.0, it means 1 request per connection.
                if efficiency < MIN_EFFICIENT_REUSE_RATIO {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: "warn".into(),
                        message: format!(
                            "Low connection efficiency ({:.2} reqs/conn). Client is not reusing connections (Keep-Alive).",
                            efficiency
                        ),
                    });
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{make_test_conn, make_test_context};
    use hyper::HeaderMap;

    #[test]
    fn check_request_no_violation_initially() {
        let rule = ConnectionEfficiency;
        let (client, state) = make_test_context();
        let method = hyper::Method::GET;
        let headers = HeaderMap::new();
        let conn = make_test_conn();

        // First request, no history
        let violation =
            rule.check_request(&client, "http://test.com", &method, &headers, &conn, &state);
        assert!(violation.is_none());
    }

    #[test]
    fn check_request_violation_low_efficiency() {
        let rule = ConnectionEfficiency;
        let (client, state) = make_test_context();
        let method = hyper::Method::GET;
        let headers = HeaderMap::new();

        // Simulate 6 connections with 1 request each (Efficiency = 1.0)
        for i in 0..6 {
            let conn = crate::connection::ConnectionMetadata::new(
                format!("127.0.0.1:{}", 12345 + i).parse().unwrap(),
            );
            state.record_connection(&client, &conn);
            state.record_transaction(&client, "http://test.com", 200, &headers);
        }

        let conn = crate::connection::ConnectionMetadata::new("127.0.0.1:12351".parse().unwrap());
        let violation =
            rule.check_request(&client, "http://test.com", &method, &headers, &conn, &state);

        assert!(violation.is_some());
        assert_eq!(violation.unwrap().rule, "connection_efficiency");
    }

    #[test]
    fn check_request_no_violation_high_efficiency() {
        let rule = ConnectionEfficiency;
        let (client, state) = make_test_context();
        let method = hyper::Method::GET;
        let headers = HeaderMap::new();

        // Simulate 1 connection with 10 requests (Efficiency = 10.0)
        let conn = make_test_conn();
        state.record_connection(&client, &conn);
        for _ in 0..10 {
            state.record_transaction(&client, "http://test.com", 200, &headers);
        }

        let violation =
            rule.check_request(&client, "http://test.com", &method, &headers, &conn, &state);
        assert!(violation.is_none());
    }
}
