// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerXFrameOptionsValueValid;

impl Rule for ServerXFrameOptionsValueValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "server_x_frame_options_value_valid"
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
        // Check response headers
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        let headers = &resp.headers;

        let count = headers.get_all("x-frame-options").iter().count();
        if count == 0 {
            return None;
        }

        if count > 1 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Multiple X-Frame-Options header fields present".into(),
            });
        }

        let val = match crate::helpers::headers::get_header_str(headers, "x-frame-options") {
            Some(v) => v.trim(),
            None => {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "X-Frame-Options header contains non-ASCII or control characters"
                        .into(),
                })
            }
        };

        if val.eq_ignore_ascii_case("DENY") || val.eq_ignore_ascii_case("SAMEORIGIN") {
            return None;
        }

        // ALLOW-FROM requires a serialized-origin per RFC 7034 and RFC 6454
        if val.len() >= 10 && val[..10].eq_ignore_ascii_case("ALLOW-FROM") {
            let rest = val[10..].trim_start();
            if rest.is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "X-Frame-Options: ALLOW-FROM missing serialized-origin".into(),
                });
            }
            // Allow a single trailing slash as examples do
            if crate::helpers::headers::is_valid_serialized_origin(rest) {
                return None;
            } else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "X-Frame-Options: ALLOW-FROM contains invalid origin: '{}'",
                        rest
                    ),
                });
            }
        }

        Some(Violation {
            rule: self.id().into(),
            severity: config.severity,
            message: format!("X-Frame-Options contains unsupported value: '{}'", val),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    use crate::test_helpers::{make_test_rule_config, make_test_transaction};

    #[rstest]
    #[case(Some("DENY"), false)]
    #[case(Some("deny"), false)]
    #[case(Some("SAMEORIGIN"), false)]
    #[case(Some("ALLOW-FROM https://example.com"), false)]
    #[case(Some("ALLOW-FROM https://example.com/"), false)]
    #[case(Some("ALLOW-FROM https://example.com:8080"), false)]
    #[case(Some("ALLOW-FROM https://[::1]"), false)]
    #[case(Some("ALLOW-FROM https://[::1]:8080"), false)]
    #[case(Some("ALLOW-FROM https://[::1]/path"), false)]
    #[case(Some("allow-from https://example.com"), false)]
    #[case(Some("ALLOW-FROM    https://example.com"), false)]
    #[case(Some("ALLOW-FROM\thttps://example.com"), false)]
    #[case(Some("ALLOW-FROM https://example.com/some/path"), false)]
    // invalid origins
    #[case(Some("ALLOW-FROM example.com"), true)]
    #[case(Some("ALLOW-FROM https://example.com:abc"), true)]
    #[case(Some("ALLOW-FROM https://user@example.com"), true)]
    #[case(Some("ALLOW-FROM https://[::1"), true)]
    // combined / comma-separated values in a single header
    #[case(Some("ALLOW-FROM https://a, ALLOW-FROM https://b"), true)]
    #[case(Some("ALLOW-FROM"), true)]
    #[case(Some("DENY, SAMEORIGIN"), true)]
    #[case(Some("SOMETHINGELSE"), true)]
    fn x_frame_cases(#[case] header_val: Option<&str>, #[case] expect_violation: bool) {
        let rule = ServerXFrameOptionsValueValid;
        let mut tx = make_test_transaction();
        if let Some(h) = header_val {
            tx = crate::test_helpers::make_test_transaction_with_response(
                200,
                &[("x-frame-options", h)],
            );
        }
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for header '{:?}', got none",
                header_val
            );
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for header '{:?}', got {:?}",
                header_val,
                v
            );
        }
    }

    #[test]
    fn multiple_headers_violation() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = ServerXFrameOptionsValueValid;
        let mut tx = make_test_transaction();
        // simulate two header occurrences by appending
        let mut hdrs = make_headers_from_pairs(&[("x-frame-options", "DENY")]);
        hdrs.append("x-frame-options", HeaderValue::from_static("SAMEORIGIN"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,

            body_length: None,
        });

        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Multiple X-Frame-Options"));
    }

    #[test]
    fn non_utf8_header_value_is_violation() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = ServerXFrameOptionsValueValid;
        let mut tx = make_test_transaction();

        let mut hdrs = make_headers_from_pairs(&[("x-frame-options", "DENY")]);
        // insert a non-utf8 header value
        hdrs.insert("x-frame-options", HeaderValue::from_bytes(&[0xff]).unwrap());

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
        let rule = ServerXFrameOptionsValueValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
