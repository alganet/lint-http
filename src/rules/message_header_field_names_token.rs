// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageHeaderFieldNamesToken;

impl Rule for MessageHeaderFieldNamesToken {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_header_field_names_token"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        // token characters per RFC token (tchar) - use shared helper
        // Check request headers
        for (k, _v) in tx.request.headers.iter() {
            if let Some(v) = check_header_name(k.as_str(), config) {
                return Some(v);
            }
        }

        // Check response headers if present
        if let Some(resp) = &tx.response {
            for (k, _v) in resp.headers.iter() {
                if let Some(v) = check_header_name(k.as_str(), config) {
                    return Some(v);
                }
            }
        }

        None
    }
}

// Extracted helper to make the message/violation formatting testable without needing
// to construct invalid `HeaderName` values (which hyper often rejects).
fn check_header_name(name: &str, config: &crate::rules::RuleConfig) -> Option<Violation> {
    if let Some(c) = crate::helpers::token::find_invalid_token_char(name) {
        return Some(Violation {
            rule: MessageHeaderFieldNamesToken.id().into(),
            severity: config.severity,
            message: format!(
                "Header field-name '{}' contains invalid character: '{}'",
                name, c
            ),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

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
            rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());

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
            rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());

        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[rstest]
    #[case("host", false, None)]
    #[case("x@bad", true, Some('@'))]
    #[case("bad header", true, Some(' '))]
    fn check_header_name_helper_cases(
        #[case] name: &str,
        #[case] expect_violation: bool,
        #[case] expected_char: Option<char>,
    ) -> anyhow::Result<()> {
        let cfg = &crate::test_helpers::make_test_rule_config();
        let res = super::check_header_name(name, cfg);

        if expect_violation {
            assert!(res.is_some(), "expected violation for '{}'", name);
            let v = res.unwrap();
            assert!(v.message.contains(name));
            if let Some(c) = expected_char {
                assert!(v.message.contains(&c.to_string()));
            }
        } else {
            assert!(res.is_none(), "expected no violation for '{}'", name);
        }
        Ok(())
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageHeaderFieldNamesToken;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
