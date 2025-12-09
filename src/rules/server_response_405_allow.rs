// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::{ClientIdentifier, StateStore};
use hyper::HeaderMap;

pub struct ServerResponse405Allow;

impl Rule for ServerResponse405Allow {
    fn id(&self) -> &'static str {
        "server_response_405_allow"
    }

    fn check_response(
        &self,
        _client: &ClientIdentifier,
        _resource: &str,
        status: u16,
        headers: &HeaderMap,
        _conn: &crate::connection::ConnectionMetadata,
        _state: &StateStore,
        _config: &crate::config::Config,
    ) -> Option<Violation> {
        if status == 405 && !headers.contains_key("allow") {
            Some(Violation {
                rule: self.id().into(),
                severity: "warn".into(),
                message: "Response 405 without Allow header".into(),
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
    fn check_response_405_missing_header() -> anyhow::Result<()> {
        let rule = ServerResponse405Allow;
        let (client, state) = make_test_context();
        let status = 405;
        let headers = HeaderMap::new();
        let conn = make_test_conn();
        let violation = rule.check_response(
            &client,
            "http://test.com",
            status,
            &headers,
            &conn,
            &state,
            &crate::config::Config::default(),
        );
        assert!(violation.is_some());
        assert_eq!(
            violation.map(|v| v.message),
            Some("Response 405 without Allow header".to_string())
        );
        Ok(())
    }

    #[test]
    fn check_response_405_present_header() -> anyhow::Result<()> {
        let rule = ServerResponse405Allow;
        let (client, state) = make_test_context();
        let status = 405;
        let mut headers = HeaderMap::new();
        headers.insert("allow", "GET, HEAD".parse()?);
        let conn = make_test_conn();
        let violation = rule.check_response(
            &client,
            "http://test.com",
            status,
            &headers,
            &conn,
            &state,
            &crate::config::Config::default(),
        );
        assert!(violation.is_none());
        Ok(())
    }

    #[test]
    fn check_response_200_missing_header() {
        let rule = ServerResponse405Allow;
        let (client, state) = make_test_context();
        let status = 200;
        let headers = HeaderMap::new();
        let conn = make_test_conn();
        let violation = rule.check_response(
            &client,
            "http://test.com",
            status,
            &headers,
            &conn,
            &state,
            &crate::config::Config::default(),
        );
        assert!(violation.is_none());
    }
}
