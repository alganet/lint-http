// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use hyper::{HeaderMap, Method};
use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::{ClientIdentifier, StateStore};

pub struct ClientUserAgentPresent;

impl Rule for ClientUserAgentPresent {
    fn id(&self) -> &'static str {
        "client_user_agent_present"
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
        if !headers.contains_key("user-agent") {
            Some(Violation {
                rule: self.id().into(),
                severity: "info".into(),
                message: "Request missing User-Agent header".into(),
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
    use crate::test_helpers::{make_test_context, make_test_conn};

    #[test]
    fn check_request_missing_header() {
        let rule = ClientUserAgentPresent;
        let (client, state) = make_test_context();
        let method = hyper::Method::GET;
        let headers = HeaderMap::new();
        let conn = make_test_conn();
        let violation = rule.check_request(&client, "http://test.com", &method, &headers, &conn, &state);
        assert!(violation.is_some());
        assert_eq!(violation.unwrap().message, "Request missing User-Agent header");
    }

    #[test]
    fn check_request_present_header() {
        let rule = ClientUserAgentPresent;
        let (client, state) = make_test_context();
        let method = hyper::Method::GET;
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "curl/7.68.0".parse().unwrap());
        let conn = make_test_conn();
        let violation = rule.check_request(&client, "http://test.com", &method, &headers, &conn, &state);
        assert!(violation.is_none());
    }
}
