// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageAcceptLanguageWeightValidity;

impl Rule for MessageAcceptLanguageWeightValidity {
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
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        // Helper to validate a single Accept-Language header value (may contain comma-separated members)
        let validate_value = |hdr_value: &str| -> Option<Violation> {
            for member in crate::helpers::headers::parse_list_header(hdr_value) {
                // Each member: language-range [; params]
                let mut iter = member.split(';').map(|s| s.trim());
                // The language-range itself is `message_language_tag_format_valid`'s
                // subject, and that deferral has been checked rather than
                // assumed: it reports an empty range, whitespace inside one, and
                // an over-long subtag, and it lets `*` through.
                let _primary = iter.next().unwrap();

                // A language-range may carry a weight. That is the whole of what
                // may follow it — `#( language-range [ weight ] )` has no
                // parameter list in it, and `weight` is the fixed shape
                // `OWS ";" OWS "q=" qvalue`. Checking that parameter names are
                // tokens and values are tokens-or-quoted-strings validated a
                // grammar this field does not have, and so called
                // `en;charset=utf-8` well formed.
                let mut weight_seen = false;
                for param in iter {
                    // Not skipped as an empty parameter slot: there are no
                    // parameter slots, and `weight` brackets nothing, so a `;`
                    // with nothing after it introduces a weight that is absent.
                    if param.is_empty() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Accept-Language member '{}' has a ';' with no weight after it",
                                member
                            ),
                        });
                    }
                    let mut nv = param.splitn(2, '=').map(|s| s.trim());
                    let name = nv.next().unwrap();
                    let val_opt = nv.next();

                    if !name.eq_ignore_ascii_case("q") {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "'{}' is not a weight, and a weight is the only thing an Accept-Language range may carry (member '{}')",
                                param, member
                            ),
                        });
                    }
                    if weight_seen {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "More than one weight in Accept-Language member '{}'",
                                member
                            ),
                        });
                    }
                    weight_seen = true;

                    let Some(val) = val_opt else {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Missing parameter value for '{}' in Accept-Language member '{}'",
                                name, member
                            ),
                        });
                    };

                    // cite(RFC 9110 § 12.4.2): "qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )"
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

    fn title(&self) -> Option<&'static str> {
        Some("Message Accept-Language Weight Validity")
    }

    fn description(&self) -> &'static str {
        "The `Accept-Language` header allows clients to specify languages and optional `q` weights that indicate preference. This rule validates that any parameters in `Accept-Language` members use valid `token` names and that `q` parameters are valid quality values in the range 0..1 with up to three decimal places."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("12.5.4"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.4",
                note: "Accept-Language",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("12.4.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.2",
                note: "Quality Values (q)",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.6"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.6",
                note: "Parameters (token / quoted-string) The rule follows the same `q`/parameter validation semantics used across other headers in this project (0..1 with up to three decimals for `q`; parameter names must be `token`; parameter values must be `token` or `quoted-string`)",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Language: en-US, fr;q=0.8",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Language: *;q=0.5, en;q=0.7",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Language: en;foo=\"a\\\"b\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Language: en;q=1.0000",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet:
                    "GET / HTTP/1.1\nHost: example.com\nAccept-Language: en;badparam=bad value",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Language: en;q=",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageAcceptLanguageWeightValidity;

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
    // A qvalue may end at the point: `0*3DIGIT` admits no digits at all.
    #[case(Some("en;q=0."), false)]
    #[case(Some("en;param=bad value"), true)]
    // A language-range may carry a weight and nothing else, so every one of
    // these is malformed however well formed the pair itself looks.
    #[case(Some("en;charset=utf-8"), true)]
    #[case(Some("en;q=0.5;foo=bar"), true)]
    // `[ weight ]` is singular.
    #[case(Some("en;q=0.5;q=0.8"), true)]
    // `weight` brackets nothing, so a `;` introducing nothing is a defect
    // wherever it sits.
    #[case(Some("en;"), true)]
    #[case(Some("en;;q=0.5"), true)]
    // The RFC's own example, and the forms the grammar does produce.
    #[case(Some("da, en-gb;q=0.8, en;q=0.7"), false)]
    #[case(Some("*;q=0"), false)]
    #[case(Some("en;Q=0.5"), false)]
    #[case(Some(""), false)]
    fn check_request_cases(
        #[case] al: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageAcceptLanguageWeightValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_language_weight_validity",
        ]);

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
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_language_weight_validity",
        ]);

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
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_language_weight_validity",
        ]);

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
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_language_weight_validity",
        ]);

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
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_language_weight_validity",
        ]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    /// `Accept-Language = #( language-range [ weight ] )` leaves no room for a
    /// `foo` parameter, well formed or not. These asserted the opposite: that a
    /// valid quoted-string value made the member acceptable, and that an
    /// invalid one was the reason to report it. The member is reported either
    /// way, and for the reason that holds for both.
    fn a_parameter_that_is_not_a_weight_is_reported_however_it_is_written() {
        let rule = MessageAcceptLanguageWeightValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_language_weight_validity",
        ]);

        for value in [
            "en;foo=\"ok\"",
            "en;foo=\"unterminated",
            "en;foo=\"a\\\"b\"",
            "en;charset=utf-8",
        ] {
            let mut tx = crate::test_helpers::make_test_transaction();
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("accept-language", value)]);
            let v = rule.check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            );
            let v = v.unwrap_or_else(|| panic!("{value:?} carries something that is not a weight"));
            assert!(v.message.contains("is not a weight"), "{value:?}: {v:?}");
        }
    }

    #[test]
    fn invalid_param_name_reports_violation() {
        let rule = MessageAcceptLanguageWeightValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_language_weight_validity",
        ]);

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
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_language_weight_validity",
        ]);

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
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_language_weight_validity",
        ]);

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
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_language_weight_validity",
        ]);

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
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_language_weight_validity",
        ]);

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
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
