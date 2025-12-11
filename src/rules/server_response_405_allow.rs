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
    use crate::test_helpers::{make_headers_from_pairs, make_test_conn, make_test_context};
    use rstest::rstest;

    #[rstest]
    #[case(405, None, true, Some("Response 405 without Allow header"))]
    #[case(405, Some(("allow", "GET, HEAD")), false, None)]
    #[case(200, None, false, None)]
    fn check_response_cases(
        #[case] status: u16,
        #[case] header: Option<(&str, &str)>,
        #[case] expect_violation: bool,
        #[case] expected_message: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = ServerResponse405Allow;
        let (client, state) = make_test_context();
        let headers = match header {
            Some((k, v)) => make_headers_from_pairs(&[(k, v)]),
            None => make_headers_from_pairs(&[]),
        };
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

        if expect_violation {
            assert!(violation.is_some());
            assert_eq!(
                violation.map(|v| v.message),
                expected_message.map(|s| s.to_string())
            );
        } else {
            assert!(violation.is_none());
        }

        Ok(())
    }
}
