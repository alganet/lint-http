// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerLocationHeaderUriValid;

impl Rule for ServerLocationHeaderUriValid {
    fn id(&self) -> &'static str {
        "server_location_header_uri_valid"
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
        let Some(resp) = &tx.response else {
            return None;
        };

        for hv in resp.headers.get_all("location") {
            let Ok(s) = hv.to_str() else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Location header value is not valid UTF-8".into(),
                });
            };

            if s.trim().is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Location header must not be empty".into(),
                });
            }

            if crate::helpers::uri::contains_whitespace(s) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Location header must not contain whitespace".into(),
                });
            }

            if let Some(msg) = crate::helpers::uri::check_percent_encoding(s) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: msg,
                });
            }

            if let Some(msg) = crate::helpers::uri::validate_scheme_if_present(s) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: msg,
                });
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Location Header URI Valid")
    }

    fn description(&self) -> &'static str {
        "This rule checks that the `Location` response header, when present, is a syntactically valid URI-reference. `Location` is commonly used in redirects and SHOULD be a URI-reference per the HTTP spec; malformed values can break clients."
    }

    fn rfc_references(&self) -> &'static [&'static str] {
        &[
            "[RFC 9110 §7.5.2](https://www.rfc-editor.org/rfc/rfc9110.html#name-location)",
            "[RFC 3986 §4](https://www.rfc-editor.org/rfc/rfc3986.html#section-4) — URI-reference syntax and percent-encoding",
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("(absolute URI)"),
                snippet: "HTTP/1.1 302 Found\nLocation: https://example.com/new-location",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(relative URI-reference)"),
                snippet: "HTTP/1.1 302 Found\nLocation: /new-location?ref=1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(invalid percent-encoding)"),
                snippet: "HTTP/1.1 302 Found\nLocation: /bad%2Gencoding",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(contains whitespace)"),
                snippet: "HTTP/1.1 302 Found\nLocation: https://example.com/ bad",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ServerLocationHeaderUriValid;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{HeaderName, HeaderValue};
    use rstest::rstest;

    fn make_tx_with_loc(loc: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 302,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("location", loc)]),

            body_length: None,
            trailers: None,
        });
        tx
    }

    #[rstest]
    #[case("https://example.com/path", false)]
    #[case("/relative/path", false)]
    #[case("/path%20with%20spaces", false)]
    #[case("", true)]
    #[case("/bad%2Gchar", true)]
    #[case("https://example.com/ bad", true)]
    fn check_location_header(#[case] loc: &str, #[case] expect_violation: bool) {
        let rule = ServerLocationHeaderUriValid;
        let tx = make_tx_with_loc(loc);
        let config = crate::test_helpers::make_test_config_with_severity(
            "server_location_header_uri_valid",
            "warn",
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}'", loc);
        } else {
            assert!(v.is_none(), "did not expect violation for '{}'", loc);
        }
    }

    #[test]
    fn non_utf8_header_value_is_violation() {
        let rule = ServerLocationHeaderUriValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        // create non-utf8 header value
        headers.insert(
            HeaderName::from_static("location"),
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 302,
            version: "HTTP/1.1".into(),
            headers,

            body_length: None,
            trailers: None,
        });

        let config = crate::test_helpers::make_test_config_with_severity(
            "server_location_header_uri_valid",
            "warn",
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("not valid UTF-8"));
    }

    #[test]
    fn invalid_scheme_start_is_violation() {
        let rule = ServerLocationHeaderUriValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 302,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("location", "1http://ex")]),

            body_length: None,
            trailers: None,
        });

        let config = crate::test_helpers::make_test_config_with_severity(
            "server_location_header_uri_valid",
            "warn",
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Invalid scheme"));
    }

    #[test]
    fn invalid_scheme_char_is_violation() {
        let rule = ServerLocationHeaderUriValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 302,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("location", "ht!tp://ex")]),

            body_length: None,
            trailers: None,
        });

        let config = crate::test_helpers::make_test_config_with_severity(
            "server_location_header_uri_valid",
            "warn",
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Invalid character"));
    }

    #[test]
    fn multiple_location_values_checked() {
        let rule = ServerLocationHeaderUriValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[("location", "/ok")]);
        headers.append("location", "bad%ZZ".parse().unwrap());
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 302,
            version: "HTTP/1.1".into(),
            headers,

            body_length: None,
            trailers: None,
        });

        let config = crate::test_helpers::make_test_config_with_severity(
            "server_location_header_uri_valid",
            "warn",
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Invalid percent-encoding"));
    }

    #[test]
    fn scope_is_server() {
        let rule = ServerLocationHeaderUriValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
