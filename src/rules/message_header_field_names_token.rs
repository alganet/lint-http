// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::StateStore;

pub struct MessageHeaderFieldNamesToken;

impl Rule for MessageHeaderFieldNamesToken {
    fn id(&self) -> &'static str {
        "message_header_field_names_token"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _conn: &crate::connection::ConnectionMetadata,
        _state: &StateStore,
        _config: &crate::config::Config,
    ) -> Option<Violation> {
        // token characters per RFC token (tchar) - use shared helper
        // Check request headers
        for (k, _v) in tx.request.headers.iter() {
            if let Some(c) = crate::token::find_invalid_token_char(k.as_str()) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: crate::rules::get_rule_severity(_config, self.id()),
                    message: format!(
                        "Header field-name '{}' contains invalid character: '{}'",
                        k.as_str(),
                        c
                    ),
                });
            }
        }

        // Check response headers if present
        if let Some(resp) = &tx.response {
            for (k, _v) in resp.headers.iter() {
                if let Some(c) = crate::token::find_invalid_token_char(k.as_str()) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: crate::rules::get_rule_severity(_config, self.id()),
                        message: format!(
                            "Header field-name '{}' contains invalid character: '{}'",
                            k.as_str(),
                            c
                        ),
                    });
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{make_test_conn, make_test_context};
    use hyper::header::HeaderName;
    use rstest::rstest;

    #[rstest]
    #[case(vec![("host", "example")], false)]
    #[case(vec![("content-type", "text/plain")], false)]
    #[case(vec![("x-custom-header", "v")], false)]
    #[case(vec![("x@bad", "v")], true)]
    #[case(vec![("bad header", "v")], true)]
    fn check_request_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageHeaderFieldNamesToken;
        let (_client, state) = make_test_context();
        let conn = make_test_conn();

        // If header name cannot be parsed into HeaderName, treat as violation (invalid header)
        for (k, _) in &header_pairs {
            if HeaderName::from_bytes(k.as_bytes()).is_err() {
                assert!(
                    expect_violation,
                    "header '{}' invalid but test expected no violation",
                    k
                );
                return Ok(());
            }
        }

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(header_pairs.as_slice());

        let violation =
            rule.check_transaction(&tx, &conn, &state, &crate::config::Config::default());

        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[rstest]
    #[case(vec![("etag", "\"abc\"")], false)]
    #[case(vec![("x@bad", "v")], true)]
    fn check_response_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageHeaderFieldNamesToken;
        let (_client, state) = make_test_context();
        let conn = make_test_conn();

        for (k, _) in &header_pairs {
            if HeaderName::from_bytes(k.as_bytes()).is_err() {
                assert!(
                    expect_violation,
                    "header '{}' invalid but test expected no violation",
                    k
                );
                return Ok(());
            }
        }

        let tx =
            crate::test_helpers::make_test_transaction_with_response(200, header_pairs.as_slice());

        let violation =
            rule.check_transaction(&tx, &conn, &state, &crate::config::Config::default());

        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }
}
