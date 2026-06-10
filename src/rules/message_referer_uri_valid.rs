// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageRefererUriValid;

impl Rule for MessageRefererUriValid {
    fn id(&self) -> &'static str {
        "message_referer_uri_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // Referer is a request header
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let req = &tx.request;

        for hv in req.headers.get_all("referer").iter() {
            let s = match hv.to_str() {
                Ok(v) => v,
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Referer header value is not valid UTF-8".into(),
                    })
                }
            };

            if s.trim().is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Referer header must not be empty".into(),
                });
            }

            if crate::helpers::uri::contains_whitespace(s) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Referer header must not contain whitespace".into(),
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
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageRefererUriValid;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{HeaderName, HeaderValue};
    use rstest::rstest;

    fn make_tx_with_referer(r: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("referer", r)]);
        tx
    }

    #[rstest]
    #[case("https://example.com/path", false)]
    #[case("/relative/path", false)]
    #[case("/path%20with%20spaces", false)]
    #[case("", true)]
    #[case("/bad%2Gchar", true)]
    #[case("https://example.com/ bad", true)]
    fn check_referer_header(#[case] referer: &str, #[case] expect_violation: bool) {
        let rule = MessageRefererUriValid;
        let tx = make_tx_with_referer(referer);
        let config = crate::test_helpers::make_test_config_with_severity(
            "message_referer_uri_valid",
            "warn",
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}'", referer);
        } else {
            assert!(v.is_none(), "did not expect violation for '{}'", referer);
        }
    }

    #[test]
    fn non_utf8_header_value_is_violation() {
        let rule = MessageRefererUriValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        // create non-utf8 header value
        headers.insert(
            HeaderName::from_static("referer"),
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.request.headers = headers;

        let config = crate::test_helpers::make_test_config_with_severity(
            "message_referer_uri_valid",
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
        let rule = MessageRefererUriValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("referer", "1http://ex")]);

        let config = crate::test_helpers::make_test_config_with_severity(
            "message_referer_uri_valid",
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
        let rule = MessageRefererUriValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("referer", "ht!tp://ex")]);

        let config = crate::test_helpers::make_test_config_with_severity(
            "message_referer_uri_valid",
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
    fn multiple_referer_values_checked() {
        let rule = MessageRefererUriValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[("referer", "/ok")]);
        headers.append("referer", "bad%ZZ".parse().unwrap());
        tx.request.headers = headers;

        let config = crate::test_helpers::make_test_config_with_severity(
            "message_referer_uri_valid",
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
    fn scope_is_client() {
        let rule = MessageRefererUriValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }
}
