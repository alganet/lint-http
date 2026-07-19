// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageAcceptEncodingParameterValidity;

impl Rule for MessageAcceptEncodingParameterValidity {
    fn id(&self) -> &'static str {
        "message_accept_encoding_parameter_validity"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        // This rule validates `Accept-Encoding` header parameters (q-values and param forms) in requests.
        for hv in tx.request.headers.get_all("accept-encoding").iter() {
            if let Ok(val) = hv.to_str() {
                // For each comma-separated member
                for part in crate::helpers::headers::parse_list_header(val) {
                    // Split into token and optional params
                    let mut iter =
                        crate::helpers::headers::split_semicolons_respecting_quotes(part)
                            .into_iter();
                    if let Some(primary) = iter.next() {
                        // primary may be '*' or token
                        if primary != "*" {
                            if let Some(c) = crate::helpers::token::find_invalid_token_char(primary)
                            {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Invalid token '{}' in Accept-Encoding header",
                                        c
                                    ),
                                });
                            }
                        }

                        for param in iter {
                            let param = param.trim();
                            if param.is_empty() {
                                continue;
                            }
                            let mut nv = param.splitn(2, '=').map(|s| s.trim());
                            let name = nv.next().unwrap();
                            let val = nv.next();

                            if crate::helpers::token::find_invalid_token_char(name).is_some() {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!("Invalid parameter name '{}' in Accept-Encoding member '{}'", name, part),
                                });
                            }

                            if val.is_none() {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!("Missing parameter value for '{}' in Accept-Encoding member '{}'", name, part),
                                });
                            }
                            let v = val.unwrap();

                            if name.eq_ignore_ascii_case("q") {
                                // cite(RFC 9110 § 12.4.2): "qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )"
                                if !crate::helpers::headers::valid_qvalue(v) {
                                    return Some(Violation {
                                        rule: self.id().into(),
                                        severity: config.severity,
                                        message: format!(
                                            "Invalid qvalue '{}' in Accept-Encoding member '{}'",
                                            v, part
                                        ),
                                    });
                                }
                            } else {
                                // value must be token or quoted-string
                                if v.starts_with('"') {
                                    if let Err(e) =
                                        crate::helpers::headers::validate_quoted_string(v)
                                    {
                                        return Some(Violation {
                                            rule: self.id().into(),
                                            severity: config.severity,
                                            message: format!("Invalid quoted-string parameter value '{}' in Accept-Encoding: {}", v, e),
                                        });
                                    }
                                } else if crate::helpers::token::find_invalid_token_char(v)
                                    .is_some()
                                {
                                    return Some(Violation {
                                        rule: self.id().into(),
                                        severity: config.severity,
                                        message: format!("Invalid parameter value '{}' for '{}' in Accept-Encoding member '{}'", v, name, part),
                                    });
                                }
                            }
                        }
                    }
                }
            } else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Accept-Encoding header value is not valid UTF-8".into(),
                });
            }
        }
        None
    }

    fn description(&self) -> &'static str {
        "`Accept-Encoding` members may include parameters such as `q` weights. This rule validates each member's parameters:\n\n- Parameter names must be `token` characters.\n- Parameter values must be a `token` or a `quoted-string`.\n- The special `q` parameter must be a valid qvalue (for example: `0`, `0.5`, `1.0`, `0.123`).\n\nInvalid parameter forms or `q` values are flagged."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("12.5.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.3",
                note: "Accept-Encoding",
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
                note: "Parameters (token / quoted-string)",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip;q=0.8",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Encoding: br;q=1.0",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(wildcard with q)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Encoding: *;q=0.5, gzip;q=0.8",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(invalid q precision)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip;q=1.0000",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(invalid coding token)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip@;q=0.5",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(missing q value)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip;q=",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageAcceptEncodingParameterValidity;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("gzip"), false)]
    #[case(Some("gzip;q=0.8"), false)]
    #[case(Some("br;q=1.0"), false)]
    #[case(Some("*, gzip;q=0.5"), false)]
    #[case(Some("gzip;q=0"), false)]
    #[case(Some("gzip;q=0.123"), false)]
    #[case(Some("gzip;q=1.000"), false)]
    #[case(Some("gzip;q=1"), false)]
    #[case(Some("gzip;Q=0.5"), false)]
    #[case(Some("gzip;q=1.0000"), true)]
    #[case(Some("x!bad;q=0.5"), false)]
    #[case(Some("gzip;q="), true)]
    #[case(Some("gzip; q=not-a-number"), true)]
    #[case(Some("gzip;q=0."), true)]
    #[case(Some("gzip;q=01.0"), true)]
    #[case(Some("gzip;q=0.1234"), true)]
    fn check_request_cases(#[case] ae: Option<&str>, #[case] expect_violation: bool) {
        let rule = MessageAcceptEncodingParameterValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_encoding_parameter_validity",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = ae {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("accept-encoding", v)]);
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
                ae.unwrap_or("<none>"),
                v
            );
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for '{}': got {:?}'",
                ae.unwrap_or("<none>"),
                v
            );
        }
    }

    #[test]
    fn non_utf8_request_header_value_is_violation() -> anyhow::Result<()> {
        let rule = MessageAcceptEncodingParameterValidity;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("accept-encoding", bad);
        tx.request.headers = hm;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_encoding_parameter_validity",
        ]);

        // Non-UTF8 header values should be considered a violation by this rule
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[rstest]
    #[case(Some("gzip;param=token"), false)]
    #[case(Some("gzip;param=\"ok\""), false)]
    #[case(Some("gzip;param=\"a;b\""), false)]
    #[case(Some("gzip;param=bad value"), true)]
    #[case(Some("gzip;param=\"unterminated"), true)]
    #[case(Some("gzip;#=1"), false)]
    #[case(Some("*;param=token"), false)]
    #[case(Some("gzip;param=\"a\\\"b\""), false)]
    #[case(Some("gzip;"), false)]
    #[case(Some("gzip; ;q=0.8"), false)]
    #[case(Some("gzip;param"), true)]
    #[case(Some("gzip;bad name=1"), true)]
    #[case(Some("gzip;q=1.0000, br;q=1.0"), true)]
    #[case(Some("gzip;q=1.0000, x!bad;q=0.5"), true)]
    #[case(Some("gzip@;q=0.5"), true)]
    #[case(Some("gzip;param=bad@val"), true)]
    fn check_additional_parameter_cases(#[case] ae: Option<&str>, #[case] expect_violation: bool) {
        let rule = MessageAcceptEncodingParameterValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_encoding_parameter_validity",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = ae {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("accept-encoding", v)]);
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
                ae.unwrap_or("<none>"),
                v
            );
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for '{}': got {:?}'",
                ae.unwrap_or("<none>"),
                v
            );
        }
    }

    #[test]
    fn multiple_header_fields_are_checked() {
        let rule = MessageAcceptEncodingParameterValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_accept_encoding_parameter_validity",
        ]);

        use hyper::header::HeaderValue;
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        headers.append("accept-encoding", HeaderValue::from_static("gzip"));
        headers.append("accept-encoding", HeaderValue::from_static("br;q=1.0000"));

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
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_accept_encoding_parameter_validity");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
