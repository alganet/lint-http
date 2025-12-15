// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::{ClientIdentifier, StateStore};
use hyper::{HeaderMap, Method};

pub struct ClientRequestMethodTokenUppercase;

impl Rule for ClientRequestMethodTokenUppercase {
    fn id(&self) -> &'static str {
        "client_request_method_token_uppercase"
    }

    fn check_request(
        &self,
        _client: &ClientIdentifier,
        _resource: &str,
        method: &Method,
        _headers: &HeaderMap,
        _conn: &crate::connection::ConnectionMetadata,
        _state: &StateStore,
        _config: &crate::config::Config,
    ) -> Option<Violation> {
        let m = method.as_str();

        // Validate token characters per RFC token (tchar). Allowed: !#$%&'*+-.^_`|~ digits letters
        let allowed = |c: char| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '!' | '#'
                        | '$'
                        | '%'
                        | '&'
                        | '\''
                        | '*'
                        | '+'
                        | '-'
                        | '.'
                        | '^'
                        | '_'
                        | '`'
                        | '|'
                        | '~'
                )
        };

        for c in m.chars() {
            if !allowed(c) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: crate::rules::get_rule_severity(_config, self.id()),
                    message: format!("Method token contains invalid character: '{}'", c),
                });
            }
            if c.is_ascii_alphabetic() && c.is_ascii_lowercase() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: crate::rules::get_rule_severity(_config, self.id()),
                    message: "Method token should be uppercase".into(),
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{make_test_conn, make_test_context};
    use rstest::rstest;

    #[rstest]
    #[case("GET", false)]
    #[case("POST", false)]
    #[case("gEt", true)]
    #[case("get", true)]
    #[case("G3T", false)]
    #[case("G-ET", false)]
    #[case("G@T", true)]
    fn check_request_cases(
        #[case] method_str: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ClientRequestMethodTokenUppercase;
        let (client, state) = make_test_context();
        let method_res = Method::from_bytes(method_str.as_bytes());
        if method_res.is_err() {
            // Invalid method token cannot be constructed; treat as violation
            assert!(
                expect_violation,
                "method '{}' invalid but test expected no violation",
                method_str
            );
            return Ok(());
        }
        let method = method_res.unwrap();
        let headers = hyper::HeaderMap::new();
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
}
