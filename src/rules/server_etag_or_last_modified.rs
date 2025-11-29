// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use hyper::HeaderMap;
use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerEtagOrLastModified;

impl Rule for ServerEtagOrLastModified {
    fn id(&self) -> &'static str {
        "server_etag_or_last_modified"
    }

    fn check_response(
        &self,
        _client: &crate::state::ClientIdentifier,
        _resource: &str,
        status: u16,
        headers: &HeaderMap,
        _state: &crate::state::StateStore,
    ) -> Option<Violation> {
        if status == 200
            && !headers.contains_key("etag")
            && !headers.contains_key("last-modified")
        {
            Some(Violation {
                rule: self.id().into(),
                severity: "info".into(),
                message: "Response 200 without ETag or Last-Modified validator".into(),
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
    fn check_response_200_missing_headers() {
        let rule = ServerEtagOrLastModified;
        let (client, state) = make_test_context();
        let status = 200;
        let headers = HeaderMap::new();
        let violation = rule.check_response(&client, "http://test.com", status, &headers, &state);
        assert!(violation.is_some());
        assert_eq!(violation.unwrap().message, "Response 200 without ETag or Last-Modified validator");
    }

    #[test]
    fn check_response_200_present_etag() {
        let rule = ServerEtagOrLastModified;
        let (client, state) = make_test_context();
        let status = 200;
        let mut headers = HeaderMap::new();
        headers.insert("etag", "\"12345\"".parse().unwrap());
        let violation = rule.check_response(&client, "http://test.com", status, &headers, &state);
        assert!(violation.is_none());
    }

    #[test]
    fn check_response_200_present_last_modified() {
        let rule = ServerEtagOrLastModified;
        let (client, state) = make_test_context();
        let status = 200;
        let mut headers = HeaderMap::new();
        headers.insert("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT".parse().unwrap());
        let violation = rule.check_response(&client, "http://test.com", status, &headers, &state);
        assert!(violation.is_none());
    }

    #[test]
    fn check_response_404_missing_headers() {
        let rule = ServerEtagOrLastModified;
        let (client, state) = make_test_context();
        let status = 404;
        let headers = HeaderMap::new();
        let violation = rule.check_response(&client, "http://test.com", status, &headers, &state);
        assert!(violation.is_none());
    }
}
