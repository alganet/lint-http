// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::{ClientIdentifier, StateStore};
use hyper::{HeaderMap, Method};

pub struct MessageContentLengthVsTransferEncoding;

impl Rule for MessageContentLengthVsTransferEncoding {
    fn id(&self) -> &'static str {
        "message_content_length_vs_transfer_encoding"
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
        if headers.contains_key("content-length") && headers.contains_key("transfer-encoding") {
            return Some(Violation {
                rule: self.id().into(),
                severity: crate::rules::get_rule_severity(_config, self.id()),
                message: "Both Content-Length and Transfer-Encoding present".into(),
            });
        }
        None
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
        if headers.contains_key("content-length") && headers.contains_key("transfer-encoding") {
            return Some(Violation {
                rule: self.id().into(),
                severity: crate::rules::get_rule_severity(_config, self.id()),
                message: "Both Content-Length and Transfer-Encoding present".into(),
            });
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
    #[case(vec![("content-length", "10"), ("transfer-encoding", "chunked")], true)]
    #[case(vec![("content-length", "10")], false)]
    #[case(vec![("transfer-encoding", "chunked")], false)]
    #[case(vec![], false)]
    fn check_request_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageContentLengthVsTransferEncoding;
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
    #[case(vec![("content-length", "10"), ("transfer-encoding", "chunked")], true)]
    #[case(vec![("content-length", "10")], false)]
    #[case(vec![("transfer-encoding", "chunked")], false)]
    #[case(vec![], false)]
    fn check_response_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageContentLengthVsTransferEncoding;
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
