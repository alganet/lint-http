// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use hyper::{HeaderMap, Method};
use crate::lint::Violation;
use crate::state::{ClientIdentifier, StateStore};
use crate::rules::Rule;

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
        
        // Only check after a few connections to avoid noise on initial load
        if count > 5 {
            if let Some(efficiency) = state.get_connection_efficiency(client) {
                // Efficiency = requests / connections.
                // If efficiency is close to 1.0, it means 1 request per connection.
                // We expect at least some reuse (e.g. > 1.1).
                if efficiency < 1.1 {
                    return Some(Violation {
                        rule: self.id().to_string(),
                        severity: "Warning".to_string(),
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
    use std::net::{IpAddr, Ipv4Addr};
    use hyper::HeaderMap;

    fn make_test_context() -> (ClientIdentifier, StateStore) {
        let client = ClientIdentifier::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            "test-agent".to_string(),
        );
        let state = StateStore::new(300);
        (client, state)
    }

    #[test]
    fn check_request_no_violation_initially() {
        let rule = ConnectionEfficiency;
        let (client, state) = make_test_context();
        let method = hyper::Method::GET;
        let headers = HeaderMap::new();
        let conn = crate::connection::ConnectionMetadata::new("127.0.0.1:12345".parse().unwrap());

        // First request, no history
        let violation = rule.check_request(&client, "http://test.com", &method, &headers, &conn, &state);
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
             let conn = crate::connection::ConnectionMetadata::new(format!("127.0.0.1:{}", 12345 + i).parse().unwrap());
             state.record_connection(&client, &conn);
             state.record_transaction(&client, "http://test.com", 200, &headers);
        }

        let conn = crate::connection::ConnectionMetadata::new("127.0.0.1:12351".parse().unwrap());
        let violation = rule.check_request(&client, "http://test.com", &method, &headers, &conn, &state);
        
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
        let conn = crate::connection::ConnectionMetadata::new("127.0.0.1:12345".parse().unwrap());
        state.record_connection(&client, &conn);
        for _ in 0..10 {
             state.record_transaction(&client, "http://test.com", 200, &headers);
        }

        let violation = rule.check_request(&client, "http://test.com", &method, &headers, &conn, &state);
        assert!(violation.is_none());
    }
}
