// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerXFrameOptionsValueValid;

impl Rule for ServerXFrameOptionsValueValid {
    fn id(&self) -> &'static str {
        "server_x_frame_options_value_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        // Check response headers
        let resp = tx.response.as_ref()?;

        let headers = &resp.headers;

        let count = headers.get_all("x-frame-options").iter().count();
        // cite(RFC 7034 § 2): "The X-Frame-Options HTTP header field indicates a policy that specifies whether the browser should render the transmitted resource"
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

        // ALLOW-FROM was RFC 7034's third variant, but the HTML Standard's
        // processing model superseded that document and dropped it: browsers treat
        // it as an unrecognized value, leaving the resource unprotected while the
        // sender believes otherwise. Flag it with a targeted message rather than
        // the generic unsupported-value one.
        if val.len() >= 10 && val[..10].eq_ignore_ascii_case("ALLOW-FROM") {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "X-Frame-Options: ALLOW-FROM is obsolete and not implemented by browsers \
                     (use the Content-Security-Policy frame-ancestors directive instead): '{}'",
                    val
                ),
            });
        }

        Some(Violation {
            rule: self.id().into(),
            severity: config.severity,
            message: format!("X-Frame-Options contains unsupported value: '{}'", val),
        })
    }

    fn description(&self) -> &'static str {
        "The `X-Frame-Options` response header protects content from being embedded in frames by other origins. This rule validates that the header, when present, uses one of the two values in the HTML Standard's conformance ABNF: `DENY` or `SAMEORIGIN` (matched case-insensitively). The `ALLOW-FROM` variant from RFC 7034 is flagged: the HTML Standard supersedes that document, browsers do not implement it, and a resource relying on it is unprotected — use the CSP `frame-ancestors` directive instead. Multiple header occurrences are also rejected."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 7034",
                section: Some("2.1"),
                url: "https://www.rfc-editor.org/rfc/rfc7034.html#section-2.1",
                note: "`X-Frame-Options` header values: `DENY`, `SAMEORIGIN`, or `ALLOW-FROM <serialized-origin>`",
            },
            crate::rules::SpecRef {
                spec: "RFC 6454",
                section: Some("6"),
                url: "https://www.rfc-editor.org/rfc/rfc6454.html#section-6",
                note: "`serialized-origin` syntax (`scheme://host[:port]`)",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nX-Frame-Options: DENY\n\n...response body...",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nX-Frame-Options: SAMEORIGIN\n\n...response body...",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("`ALLOW-FROM` is obsolete and not implemented"),
                snippet: "HTTP/1.1 200 OK\nX-Frame-Options: ALLOW-FROM https://example.com/\n\n...response body...",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nX-Frame-Options: DENY, SAMEORIGIN\n\n...response body...",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nX-Frame-Options: SOMETHINGELSE\n\n...response body...",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ServerXFrameOptionsValueValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    use crate::test_helpers::make_test_transaction;

    #[rstest]
    #[case(Some("DENY"), false)]
    #[case(Some("deny"), false)]
    #[case(Some("SAMEORIGIN"), false)]
    #[case(Some("sameorigin"), false)]
    // ALLOW-FROM is obsolete: the HTML Standard's conformance ABNF admits only
    // DENY / SAMEORIGIN, and browsers do not implement ALLOW-FROM.
    #[case(Some("ALLOW-FROM https://example.com"), true)]
    #[case(Some("ALLOW-FROM https://example.com/"), true)]
    #[case(Some("allow-from https://example.com"), true)]
    #[case(Some("ALLOW-FROM\thttps://example.com"), true)]
    #[case(Some("ALLOW-FROM example.com"), true)]
    #[case(Some("ALLOW-FROM"), true)]
    // combined / comma-separated values in a single header
    #[case(Some("ALLOW-FROM https://a, ALLOW-FROM https://b"), true)]
    #[case(Some("DENY, SAMEORIGIN"), true)]
    #[case(Some("SOMETHINGELSE"), true)]
    #[case(Some("ALLOWALL"), true)]
    fn x_frame_cases(#[case] header_val: Option<&str>, #[case] expect_violation: bool) {
        let rule = ServerXFrameOptionsValueValid;
        let mut tx = make_test_transaction();
        if let Some(h) = header_val {
            tx = crate::test_helpers::make_test_transaction_with_response(
                200,
                &[("x-frame-options", h)],
            );
        }
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
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
    fn allow_from_violation_names_the_replacement() {
        let rule = ServerXFrameOptionsValueValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("x-frame-options", "ALLOW-FROM https://example.com")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let v = v.expect("ALLOW-FROM must be flagged");
        assert!(v.message.contains("obsolete"));
        assert!(v.message.contains("frame-ancestors"));
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
            trailers: None,
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
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
            trailers: None,
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-ASCII"));
    }

    #[test]
    fn scope_is_server() {
        let rule = ServerXFrameOptionsValueValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
