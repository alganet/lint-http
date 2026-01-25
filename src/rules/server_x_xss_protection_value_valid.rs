// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerXXssProtectionValueValid;

impl Rule for ServerXXssProtectionValueValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "server_x_xss_protection_value_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        let headers = &resp.headers;
        let count = headers.get_all("x-xss-protection").iter().count();
        if count == 0 {
            return None;
        }

        if count > 1 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Multiple X-XSS-Protection header fields present".into(),
            });
        }

        let val = match crate::helpers::headers::get_header_str(headers, "x-xss-protection") {
            Some(v) => v.trim(),
            None => {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "X-XSS-Protection header contains non-ASCII or control characters"
                        .into(),
                })
            }
        };

        // Accept exactly "0" or "1;mode=block" (allow whitespace around separators, case-insensitive)
        if val.eq_ignore_ascii_case("0") {
            return None;
        }

        // Split on ';' and validate structure: exactly two parts, first is '1', second is 'mode=block'
        let parts: Vec<&str> = val.split(';').map(|s| s.trim()).collect();
        if parts.len() == 2
            && parts[0].eq_ignore_ascii_case("1")
            && parts[1].eq_ignore_ascii_case("mode=block")
        {
            return None;
        }

        Some(Violation {
            rule: self.id().into(),
            severity: config.severity,
            message: format!("X-XSS-Protection contains unsupported value: '{}'", val),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    use crate::test_helpers::{make_test_rule_config, make_test_transaction};

    #[rstest]
    #[case(Some("0"), false)]
    #[case(Some("0 "), false)]
    #[case(Some("1;mode=block"), false)]
    #[case(Some("1; mode=block"), false)]
    #[case(Some("1;MODE=BLOCK"), false)]
    #[case(Some("1;  mode=block  "), false)]
    // invalid values
    #[case(Some("1"), true)]
    #[case(Some("2"), true)]
    #[case(Some("1;report=1"), true)]
    #[case(Some("1; mode=none"), true)]
    #[case(Some(""), true)]
    fn check_header_values(#[case] val: Option<&str>, #[case] expect_violation: bool) {
        let rule = ServerXXssProtectionValueValid;
        let mut tx = make_test_transaction();
        if let Some(v) = val {
            tx = crate::test_helpers::make_test_transaction_with_response(
                200,
                &[("x-xss-protection", v)],
            );
        }

        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{:?}', got none", val);
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for '{:?}', got {:?}",
                val,
                v
            );
        }
    }

    #[test]
    fn multiple_headers_violation() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = ServerXXssProtectionValueValid;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("x-xss-protection", "0")]);
        hdrs.append("x-xss-protection", HeaderValue::from_static("1;mode=block"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,

            body_length: None,
        });

        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Multiple X-XSS-Protection"));
    }

    #[test]
    fn non_utf8_header_value_is_violation() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = ServerXXssProtectionValueValid;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("x-xss-protection", "0")]);
        hdrs.insert(
            "x-xss-protection",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,

            body_length: None,
        });

        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-ASCII"));
    }

    #[test]
    fn scope_is_server() {
        let rule = ServerXXssProtectionValueValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn no_response_returns_none() {
        let rule = ServerXXssProtectionValueValid;
        let tx = make_test_transaction(); // no response set
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn response_without_header_returns_none() {
        let rule = ServerXXssProtectionValueValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn unsupported_value_message_contains_value() {
        let rule = ServerXXssProtectionValueValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("x-xss-protection", "1")],
        );
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("1"));
    }

    #[test]
    fn extra_semicolon_is_violation_and_reported() {
        let rule = ServerXXssProtectionValueValid;
        let val = "1;mode=block;";
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("x-xss-protection", val)],
        );
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("unsupported value") && m.contains(val));
    }

    #[test]
    fn comma_separated_values_are_violation() {
        let rule = ServerXXssProtectionValueValid;
        let val = "0, 1;mode=block";
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("x-xss-protection", val)],
        );
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("unsupported value") && m.contains("0, 1;mode=block"));
    }
}
