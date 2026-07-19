// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageEarlyDataHeaderSafeMethod;

impl Rule for MessageEarlyDataHeaderSafeMethod {
    fn id(&self) -> &'static str {
        "message_early_data_header_safe_method"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // This rule applies to client requests only
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        // Early-Data is defined as a request header (RFC 8470). If present and equal to '1',
        // it should only be used with safe methods (GET, HEAD, OPTIONS, TRACE).
        // A request may include multiple Early-Data header fields. Per RFC 8470, any
        // instance whose value is "1" indicates the request may have been sent in
        // early data and must therefore be restricted to safe methods. Iterate over
        // all header instances and consider any valid UTF-8 value equal to "1".
        for hv in tx.request.headers.get_all("early-data").iter() {
            if let Ok(s) = hv.to_str() {
                if s.trim() == "1" {
                    let m = tx.request.method.trim().to_ascii_uppercase();
                    if !(m == "GET" || m == "HEAD" || m == "OPTIONS" || m == "TRACE") {
                        return Some(Violation {
                            rule: MessageEarlyDataHeaderSafeMethod.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Invalid Early-Data header on non-safe method '{}'; Early-Data: 1 is only allowed on safe methods",
                                tx.request.method
                            ),
                        });
                    }
                }
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "If a request includes `Early-Data: 1`, the request method must be one of the safe methods: `GET`, `HEAD`, `OPTIONS`, or `TRACE`. Presence of `Early-Data: 1` on non-safe methods such as `POST`, `PUT`, or `DELETE` may indicate misuse of early data and is flagged as a violation."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 8470",
                section: Some("4"),
                url: "https://www.rfc-editor.org/rfc/rfc8470.html#section-4",
                note: "Using Early Data in HTTP Clients — Clients MUST NOT send unsafe methods (or methods whose safety is unknown) in early data",
            },
            crate::rules::SpecRef {
                spec: "RFC 8470",
                section: Some("5.1"),
                url: "https://www.rfc-editor.org/rfc/rfc8470.html#section-5.1",
                note: "The Early-Data Header Field — The `Early-Data` header field has the single valid value `\"1\"` and indicates the request may have been sent in early data",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example\nEarly-Data: 1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "POST /submit HTTP/1.1\nHost: example\nEarly-Data: 1",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageEarlyDataHeaderSafeMethod;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    #[rstest]
    #[case("GET", Some("1"), false)]
    #[case("HEAD", Some("1"), false)]
    #[case("OPTIONS", Some("1"), false)]
    #[case("TRACE", Some("1"), false)]
    #[case("POST", Some("1"), true)]
    #[case("PUT", Some("1"), true)]
    #[case("DELETE", Some("1"), true)]
    #[case("GET", Some("0"), false)]
    #[case("POST", Some("0"), false)]
    #[case("GET", None, false)]
    fn early_data_header_cases(
        #[case] method: &str,
        #[case] header: Option<&str>,
        #[case] expect_violation: bool,
    ) {
        let rule = MessageEarlyDataHeaderSafeMethod;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_early_data_header_safe_method",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = method.to_string();
        if let Some(h) = header {
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("early-data", h)]);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for {:?} {:?}",
                method,
                header
            );
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for {:?} {:?}: {:?}",
                method,
                header,
                v
            );
        }
    }

    #[test]
    fn scope_is_client() {
        let rule = MessageEarlyDataHeaderSafeMethod;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = MessageEarlyDataHeaderSafeMethod;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_early_data_header_safe_method",
        ]);
        rule.validate(&cfg)?;
        Ok(())
    }

    #[test]
    fn multiple_header_instances_with_one_1_reports_violation() {
        let rule = MessageEarlyDataHeaderSafeMethod;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_early_data_header_safe_method",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "POST".to_string();

        let mut hm = hyper::HeaderMap::new();
        hm.append("early-data", "0".parse::<HeaderValue>().unwrap());
        hm.append("early-data", "1".parse::<HeaderValue>().unwrap());
        tx.request.headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn non_utf8_header_value_is_ignored() {
        let rule = MessageEarlyDataHeaderSafeMethod;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_early_data_header_safe_method",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "POST".to_string();

        let mut hm = hyper::HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should create non-utf8");
        hm.append("early-data", bad);
        tx.request.headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }
}
