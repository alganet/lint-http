// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageAcceptLanguageWeightValidity;

impl Rule for MessageAcceptLanguageWeightValidity {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_accept_language_weight_validity"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Helper to validate a single Accept-Language header value (may contain comma-separated members)
        let validate_value = |hdr_value: &str| -> Option<Violation> {
            for member in crate::helpers::headers::parse_list_header(hdr_value) {
                // Each member: language-range [; params]
                let mut iter = member.split(';').map(|s| s.trim());
                let _primary = iter.next().unwrap(); // primary language-range already validated elsewhere

                for param in iter {
                    if param.is_empty() {
                        continue;
                    }
                    let mut nv = param.splitn(2, '=').map(|s| s.trim());
                    let name = nv.next().unwrap();
                    let val_opt = nv.next();

                    if crate::helpers::token::find_invalid_token_char(name).is_some() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Invalid parameter name '{}' in Accept-Language member '{}'",
                                name, member
                            ),
                        });
                    }

                    if val_opt.is_none() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Missing parameter value for '{}' in Accept-Language member '{}'",
                                name, member
                            ),
                        });
                    }
                    let val = val_opt.unwrap();

                    if name.eq_ignore_ascii_case("q") {
                        if !crate::helpers::headers::valid_qvalue(val) {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Invalid qvalue '{}' in Accept-Language member '{}'",
                                    val, member
                                ),
                            });
                        }
                    } else {
                        // Other parameter values must be token or quoted-string
                        if val.starts_with('"') {
                            if let Err(e) = crate::helpers::headers::validate_quoted_string(val) {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!("Invalid quoted-string parameter value '{}' in Accept-Language: {}", val, e),
                                });
                            }
                        } else if crate::helpers::token::find_invalid_token_char(val).is_some() {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!("Invalid parameter value '{}' for '{}' in Accept-Language member '{}'", val, name, member),
                            });
                        }
                    }
                }
            }
            None
        };

        // Request
        for hv in tx.request.headers.get_all("accept-language").iter() {
            if let Ok(val) = hv.to_str() {
                if let Some(v) = validate_value(val) {
                    return Some(v);
                }
            } else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Accept-Language header value is not valid UTF-8".into(),
                });
            }
        }

        // Response (some servers echo Accept-Language; be conservative)
        if let Some(resp) = &tx.response {
            for hv in resp.headers.get_all("accept-language").iter() {
                if let Ok(val) = hv.to_str() {
                    if let Some(v) = validate_value(val) {
                        return Some(v);
                    }
                } else {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Accept-Language header value is not valid UTF-8".into(),
                    });
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("en"), false)]
    #[case(Some("en;q=0.8"), false)]
    #[case(Some("zh;q=0"), false)]
    #[case(Some("en-US;q=1.0"), false)]
    #[case(Some("*, en;q=0.5"), false)]
    #[case(Some("en;q=1.0000"), true)]
    #[case(Some("en;q="), true)]
    #[case(Some("en;q=0."), true)]
    #[case(Some("en;param=bad value"), true)]
    fn check_request_cases(
        #[case] al: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageAcceptLanguageWeightValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = al {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("accept-language", v)]);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for '{}': got {:?}'",
                al.unwrap_or("<none>"),
                v
            );
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for '{}': got {:?}'",
                al.unwrap_or("<none>"),
                v
            );
        }
        Ok(())
    }

    #[test]
    fn non_utf8_header_value_is_violation() -> anyhow::Result<()> {
        let rule = MessageAcceptLanguageWeightValidity;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("accept-language", bad);
        tx.request.headers = hm;
        let cfg = crate::test_helpers::make_test_rule_config();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn multiple_header_fields_are_checked() {
        let rule = MessageAcceptLanguageWeightValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        use hyper::header::HeaderValue;
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        headers.append("accept-language", HeaderValue::from_static("en, fr;q=0.5"));
        headers.append("accept-language", HeaderValue::from_static("zh;q=1.0000"));

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = headers;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn response_header_invalid_q_reports_violation() {
        let rule = MessageAcceptLanguageWeightValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept-language", "en;q=1.0000")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn response_non_utf8_header_value_is_violation() -> anyhow::Result<()> {
        let rule = MessageAcceptLanguageWeightValidity;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("accept-language", bad);
        tx.response.as_mut().unwrap().headers = hm;
        let cfg = crate::test_helpers::make_test_rule_config();

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn other_param_quoted_string_valid_and_invalid() {
        let rule = MessageAcceptLanguageWeightValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        // valid quoted-string
        let mut tx1 = crate::test_helpers::make_test_transaction();
        tx1.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept-language", "en;foo=\"ok\"")]);
        assert!(rule
            .check_transaction(
                &tx1,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_none());

        // invalid quoted-string
        let mut tx2 = crate::test_helpers::make_test_transaction();
        tx2.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "accept-language",
            "en;foo=\"unterminated",
        )]);
        assert!(rule
            .check_transaction(
                &tx2,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_some());
    }

    #[test]
    fn invalid_param_name_reports_violation() {
        let rule = MessageAcceptLanguageWeightValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept-language", "en;b@d=1")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn param_without_value_reports_violation() {
        let rule = MessageAcceptLanguageWeightValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept-language", "en;param")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn wildcard_with_q_ok() {
        let rule = MessageAcceptLanguageWeightValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept-language", "*;q=0.5")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn uppercase_q_parameter_name_is_accepted() {
        let rule = MessageAcceptLanguageWeightValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept-language", "en;Q=0.5")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn multiple_header_fields_all_valid_no_violation() {
        let rule = MessageAcceptLanguageWeightValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        use hyper::header::HeaderValue;
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        headers.append("accept-language", HeaderValue::from_static("en;q=1.0"));
        headers.append("accept-language", HeaderValue::from_static("fr;q=0.8"));

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = headers;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn quoted_string_with_escaped_quote_valid() {
        let rule = MessageAcceptLanguageWeightValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        // quoted-string with escaped quote: "a\"b"
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "accept-language",
            "en;foo=\"a\\\"b\"",
        )]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageAcceptLanguageWeightValidity;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn message_and_id() {
        let rule = MessageAcceptLanguageWeightValidity;
        assert_eq!(rule.id(), "message_accept_language_weight_validity");
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_accept_language_weight_validity");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
