// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use hyper::HeaderMap;
use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::{ClientIdentifier, StateStore};

pub struct ServerXContentTypeOptions;

impl Rule for ServerXContentTypeOptions {
    fn id(&self) -> &'static str {
        "server_x_content_type_options"
    }

    fn check_response(
        &self,
        _client: &ClientIdentifier,
        _resource: &str,
        status: u16,
        headers: &HeaderMap,
        _conn: &crate::connection::ConnectionMetadata,
        _state: &StateStore,
    ) -> Option<Violation> {
        if (200..300).contains(&status) && !headers.contains_key("x-content-type-options") {
            Some(Violation {
                rule: self.id().into(),
                severity: "warn".into(),
                message: "Missing X-Content-Type-Options: nosniff header".into(),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::HeaderMap;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_test_context() -> (crate::state::ClientIdentifier, crate::state::StateStore) {
        let client = crate::state::ClientIdentifier::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            "test-agent".to_string(),
        );
        let state = crate::state::StateStore::new(300);
        (client, state)
    }

    #[test]
    fn check_response_200_missing_header() {
        let rule = ServerXContentTypeOptions;
        let (client, state) = make_test_context();
        let status = 200;
        let headers = HeaderMap::new();
        let conn = crate::connection::ConnectionMetadata::new("127.0.0.1:12345".parse().unwrap());
        let violation = rule.check_response(&client, "http://test.com", status, &headers, &conn, &state);
        assert!(violation.is_some());
        assert_eq!(violation.unwrap().message, "Missing X-Content-Type-Options: nosniff header");
    }

    #[test]
    fn check_response_200_present_header() {
        let rule = ServerXContentTypeOptions;
        let (client, state) = make_test_context();
        let status = 200;
        let mut headers = HeaderMap::new();
        headers.insert("x-content-type-options", "nosniff".parse().unwrap());
        let conn = crate::connection::ConnectionMetadata::new("127.0.0.1:12345".parse().unwrap());
        let violation = rule.check_response(&client, "http://test.com", status, &headers, &conn, &state);
        assert!(violation.is_none());
    }

    #[test]
    fn check_response_404_missing_header() {
        let rule = ServerXContentTypeOptions;
        let (client, state) = make_test_context();
        let status = 404;
        let headers = HeaderMap::new();
        let conn = crate::connection::ConnectionMetadata::new("127.0.0.1:12345".parse().unwrap());
        let violation = rule.check_response(&client, "http://test.com", status, &headers, &conn, &state);
        assert!(violation.is_none());
    }

    #[test]
    fn check_response_101_missing_header() {
        let rule = ServerXContentTypeOptions;
        let (client, state) = make_test_context();
        let status = 101;
        let headers = HeaderMap::new();
        let conn = crate::connection::ConnectionMetadata::new("127.0.0.1:12345".parse().unwrap());
        let violation = rule.check_response(&client, "http://test.com", status, &headers, &conn, &state);
        assert!(violation.is_none());
    }
}
