// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerLocationHeaderUriValid;

impl Rule for ServerLocationHeaderUriValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "server_location_header_uri_valid"
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

        for hv in resp.headers.get_all("location").iter() {
            let s = match hv.to_str() {
                Ok(v) => v,
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Location header value is not valid UTF-8".into(),
                    })
                }
            };

            if s.trim().is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Location header must not be empty".into(),
                });
            }

            if crate::rules::uri::contains_whitespace(s) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Location header must not contain whitespace".into(),
                });
            }

            if let Some(msg) = crate::rules::uri::check_percent_encoding(s) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: msg,
                });
            }

            if let Some(msg) = crate::rules::uri::validate_scheme_if_present(s) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: msg,
                });
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{HeaderName, HeaderValue};
    use rstest::rstest;

    fn make_tx_with_loc(loc: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 302,
            headers: crate::test_helpers::make_headers_from_pairs(&[("location", loc)]),
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
        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        let v = rule.check_transaction(&tx, None, &config);
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
            headers,
        });

        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        let v = rule.check_transaction(&tx, None, &config);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("not valid UTF-8"));
    }

    #[test]
    fn invalid_scheme_start_is_violation() {
        let rule = ServerLocationHeaderUriValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 302,
            headers: crate::test_helpers::make_headers_from_pairs(&[("location", "1http://ex")]),
        });

        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        let v = rule.check_transaction(&tx, None, &config);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Invalid scheme"));
    }

    #[test]
    fn invalid_scheme_char_is_violation() {
        let rule = ServerLocationHeaderUriValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 302,
            headers: crate::test_helpers::make_headers_from_pairs(&[("location", "ht!tp://ex")]),
        });

        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        let v = rule.check_transaction(&tx, None, &config);
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
            headers,
        });

        let config = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };
        let v = rule.check_transaction(&tx, None, &config);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Invalid percent-encoding"));
    }

    #[test]
    fn scope_is_server() {
        let rule = ServerLocationHeaderUriValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
