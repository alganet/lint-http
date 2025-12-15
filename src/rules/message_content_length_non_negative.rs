// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::{ClientIdentifier, StateStore};
use hyper::{HeaderMap, Method};

pub struct MessageContentLengthNonNegative;

impl Rule for MessageContentLengthNonNegative {
    fn id(&self) -> &'static str {
        "message_content_length_non_negative"
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
        self.check_content_length_headers(headers, _config)
    }

    fn check_response(
        &self,
        _client: &ClientIdentifier,
        _resource: &str,
        _status: u16,
        headers: &HeaderMap,
        _conn: &crate::connection::ConnectionMetadata,
        _state: &StateStore,
        _config: &crate::config::Config,
    ) -> Option<Violation> {
        self.check_content_length_headers(headers, _config)
    }
}

impl MessageContentLengthNonNegative {
    fn check_content_length_headers(
        &self,
        headers: &HeaderMap,
        _config: &crate::config::Config,
    ) -> Option<Violation> {
        for val in headers.get_all("content-length").iter() {
            if let Ok(s) = val.to_str() {
                let t = s.trim();
                if t.is_empty() || !t.chars().all(|c| c.is_ascii_digit()) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: crate::rules::get_rule_severity(_config, self.id()),
                        message: format!("Invalid Content-Length value: '{}'", s),
                    });
                }
            } else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: crate::rules::get_rule_severity(_config, self.id()),
                    message: "Invalid Content-Length header encoding".into(),
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{make_headers_from_pairs, make_test_conn, make_test_context};
    use rstest::rstest;

    #[rstest]
    #[case(vec![("content-length", "10")], false)]
    #[case(vec![("content-length", "0")], false)]
    #[case(vec![("content-length", "  20  ")], false)]
    #[case(vec![("content-length", "+1")], true)]
    #[case(vec![("content-length", "-1")], true)]
    #[case(vec![("content-length", "1.5")], true)]
    #[case(vec![("content-length", "abc")], true)]
    #[case(vec![("content-length", "")], true)]
    #[case(vec![("content-length", "10"), ("content-length", "20")], false)]
    fn check_request_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageContentLengthNonNegative;
        let (client, state) = make_test_context();
        let method = hyper::Method::POST;
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
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[rstest]
    #[case(vec![("content-length", "10")], false)]
    #[case(vec![("content-length", "-1")], true)]
    #[case(vec![("content-length", "abc")], true)]
    #[case(vec![("content-length", "")], true)]
    fn check_response_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageContentLengthNonNegative;
        let (client, state) = make_test_context();
        let status = 200;
        let headers = make_headers_from_pairs(&header_pairs);
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
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }
}
