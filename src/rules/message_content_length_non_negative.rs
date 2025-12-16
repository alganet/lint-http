// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::StateStore;

pub struct MessageContentLengthNonNegative;

impl Rule for MessageContentLengthNonNegative {
    fn id(&self) -> &'static str {
        "message_content_length_non_negative"
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
        // Check request headers
        for (k, v) in tx.request.headers.iter() {
            if k.as_str().eq_ignore_ascii_case("content-length") {
                let s = match v.to_str() {
                    Ok(s) => s,
                    Err(_) => {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: crate::rules::get_rule_severity(_config, self.id()),
                            message: "Invalid Content-Length value (non-UTF8)".into(),
                        })
                    }
                };
                let t = s.trim();
                if t.is_empty() || !t.chars().all(|c| c.is_ascii_digit()) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: crate::rules::get_rule_severity(_config, self.id()),
                        message: format!("Invalid Content-Length value: '{}'", s),
                    });
                }
            }
        }

        // Check response headers if present
        if let Some(resp) = &tx.response {
            for (k, v) in resp.headers.iter() {
                if k.as_str().eq_ignore_ascii_case("content-length") {
                    let s = match v.to_str() {
                        Ok(s) => s,
                        Err(_) => {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: crate::rules::get_rule_severity(_config, self.id()),
                                message: "Invalid Content-Length value (non-UTF8)".into(),
                            })
                        }
                    };
                    let t = s.trim();
                    if t.is_empty() || !t.chars().all(|c| c.is_ascii_digit()) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: crate::rules::get_rule_severity(_config, self.id()),
                            message: format!("Invalid Content-Length value: '{}'", s),
                        });
                    }
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
        let (_client, _state) = make_test_context();
        let conn = make_test_conn();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(header_pairs.as_slice());

        let violation =
            rule.check_transaction(&tx, &conn, &_state, &crate::config::Config::default());

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
        let (_client, _state) = make_test_context();
        let status = 200;
        let conn = make_test_conn();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            headers: crate::test_helpers::make_headers_from_pairs(header_pairs.as_slice()),
        });

        let violation =
            rule.check_transaction(&tx, &conn, &_state, &crate::config::Config::default());

        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }
}
