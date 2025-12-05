// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::{ClientIdentifier, StateStore};
use hyper::{HeaderMap, Method};

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
    use crate::test_helpers::{make_test_conn, make_test_context};
    use hyper::HeaderMap;

    #[test]
    fn check_request_missing_header() -> anyhow::Result<()> {
        let rule = ClientAcceptEncodingPresent;
        let (client, state) = make_test_context();
        let method = hyper::Method::GET;
        let headers = HeaderMap::new();
        let conn = make_test_conn();
        let violation =
            rule.check_request(&client, "http://test.com", &method, &headers, &conn, &state);
        assert!(violation.is_some());
        assert_eq!(
            violation.map(|v| v.message),
            Some("Request missing Accept-Encoding header".to_string())
        );
        Ok(())
    }

    #[test]
    fn check_request_present_header() -> anyhow::Result<()> {
        let rule = ClientAcceptEncodingPresent;
        let (client, state) = make_test_context();
        let method = hyper::Method::GET;
        let mut headers = HeaderMap::new();
        headers.insert("accept-encoding", "gzip".parse()?);
        let conn = make_test_conn();
        let violation =
            rule.check_request(&client, "http://test.com", &method, &headers, &conn, &state);
        assert!(violation.is_none());
        Ok(())
    }
}
