// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::{ClientIdentifier, StateStore};
use hyper::HeaderMap;

pub struct ServerCacheControlPresent;

impl Rule for ServerCacheControlPresent {
    fn id(&self) -> &'static str {
        "server_cache_control_present"
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
        if status == 200 && !headers.contains_key("cache-control") {
            Some(Violation {
                rule: self.id().into(),
                severity: "warn".into(),
                message: "Response 200 without Cache-Control header".into(),
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
    fn check_response_200_missing_header() -> anyhow::Result<()> {
        let rule = ServerCacheControlPresent;
        let (client, state) = make_test_context();
        let status = 200;
        let headers = HeaderMap::new();
        let conn = make_test_conn();
        let violation =
            rule.check_response(&client, "http://test.com", status, &headers, &conn, &state);
        assert!(violation.is_some());
        assert_eq!(
            violation.map(|v| v.message),
            Some("Response 200 without Cache-Control header".to_string())
        );
        Ok(())
    }

    #[test]
    fn check_response_200_present_header() -> anyhow::Result<()> {
        let rule = ServerCacheControlPresent;
        let (client, state) = make_test_context();
        let status = 200;
        let mut headers = HeaderMap::new();
        headers.insert("cache-control", "no-cache".parse()?);
        let conn = make_test_conn();
        let violation =
            rule.check_response(&client, "http://test.com", status, &headers, &conn, &state);
        assert!(violation.is_none());
        Ok(())
    }

    #[test]
    fn check_response_404_missing_header() {
        let rule = ServerCacheControlPresent;
        let (client, state) = make_test_context();
        let status = 404;
        let headers = HeaderMap::new();
        let conn = make_test_conn();
        let violation =
            rule.check_response(&client, "http://test.com", status, &headers, &conn, &state);
        assert!(violation.is_none());
    }
}
