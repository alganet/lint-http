// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use hyper::{HeaderMap, Method};
use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::{ClientIdentifier, StateStore};

pub struct ClientAcceptEncodingPresent;

impl Rule for ClientAcceptEncodingPresent {
    fn id(&self) -> &'static str {
        "client_accept_encoding_present"
    }

    fn check_request(
        &self,
        _client: &ClientIdentifier,
        _resource: &str,
        _method: &Method,
        headers: &HeaderMap,
        _conn: &crate::connection::ConnectionMetadata,
        _state: &StateStore,
    ) -> Option<Violation> {
        if !headers.contains_key("accept-encoding") {
            Some(Violation {
                rule: self.id().into(),
                severity: "info".into(),
                message: "Request missing Accept-Encoding header".into(),
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
    fn check_request_missing_header() {
        let rule = ClientAcceptEncodingPresent;
        let (client, state) = make_test_context();
        let method = hyper::Method::GET;
        let headers = HeaderMap::new();
        let conn = crate::connection::ConnectionMetadata::new("127.0.0.1:12345".parse().unwrap());
        let violation = rule.check_request(&client, "http://test.com", &method, &headers, &conn, &state);
        assert!(violation.is_some());
        assert_eq!(violation.unwrap().message, "Request missing Accept-Encoding header");
    }

    #[test]
    fn check_request_present_header() {
        let rule = ClientAcceptEncodingPresent;
        let (client, state) = make_test_context();
        let method = hyper::Method::GET;
        let mut headers = HeaderMap::new();
        headers.insert("accept-encoding", "gzip".parse().unwrap());
        let conn = crate::connection::ConnectionMetadata::new("127.0.0.1:12345".parse().unwrap());
        let violation = rule.check_request(&client, "http://test.com", &method, &headers, &conn, &state);
        assert!(violation.is_none());
    }
}
