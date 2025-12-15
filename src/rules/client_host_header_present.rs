// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::{ClientIdentifier, StateStore};
use hyper::{HeaderMap, Method};

pub struct ClientHostHeaderPresent;

impl Rule for ClientHostHeaderPresent {
    fn id(&self) -> &'static str {
        "client_host_header_present"
    }

    fn check_request(
        &self,
        _client: &ClientIdentifier,
        _resource: &str,
        _method: &Method,
        headers: &HeaderMap,
        _conn: &crate::connection::ConnectionMetadata,
        _state: &StateStore,
        _config: &crate::config::Config,
    ) -> Option<Violation> {
        if !headers.contains_key("host") {
            Some(Violation {
                rule: self.id().into(),
                severity: crate::rules::get_rule_severity(_config, self.id()),
                message: "Request missing Host header".into(),
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
    #[case(vec![], true, Some("Request missing Host header"))]
    #[case(vec![("host", "example.com")], false, None)]
    fn check_request_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
        #[case] expected_message: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = ClientHostHeaderPresent;
        let (client, state) = make_test_context();
        let method = hyper::Method::GET;
        let headers = make_headers_from_pairs(&header_pairs);
        let conn = make_test_conn();
        let violation = rule.check_request(
            &client,
            "http://test.com",
            &method,
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
