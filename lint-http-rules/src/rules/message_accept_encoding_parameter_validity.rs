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
                        // `codings` is a content-coding, the literal "identity",
                        // or the literal "*", and the first two of those are
                        // tokens. A token is one or more characters, which a
                        // scan for an invalid character cannot tell you: an
                        // empty string has no invalid character in it, so
                        // `;q=0.5` — a member that is all weight and no coding —
                        // passed on exactly that reasoning.
                        if primary != "*" {
                            if primary.is_empty() {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Empty content-coding in Accept-Encoding member '{}'",
                                        part
                                    ),
                                });
                            }
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

                        // Everything after the coding must be a weight. There is
                        // no parameter list here to be well formed — the whole
                        // member is `codings [ weight ]`, and `weight` is the
                        // fixed shape `OWS ";" OWS "q=" qvalue`. Validating
                        // arbitrary `name=value` pairs answered a question this
                        // field does not ask, and answered it in the direction
                        // that matters: `gzip;charset=utf-8` was called well
                        // formed, when nothing in the grammar produces it.
                        let mut weight_seen = false;
                        for param in iter {
                            let param = param.trim();
                            // Not skipped as an empty parameter slot, because
                            // there are no parameter slots. `weight` brackets
                            // nothing, so a `;` with nothing after it is a
                            // separator introducing a weight that is not there.
                            if param.is_empty() {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Accept-Encoding member '{}' ends in ';' with no weight after it",
                                        part
                                    ),
                                });
                            }

                            let mut nv = param.splitn(2, '=').map(|s| s.trim());
                            let name = nv.next().unwrap();
                            let val = nv.next();

                            if !name.eq_ignore_ascii_case("q") {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "'{}' is not a weight, and a weight is the only thing an Accept-Encoding coding may carry (member '{}')",
                                        param, part
                                    ),
                                });
                            }
                            if weight_seen {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "More than one weight in Accept-Encoding member '{}'",
                                        part
                                    ),
                                });
                            }
                            weight_seen = true;

                            let Some(v) = val else {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!(
                                        "Missing parameter value for '{}' in Accept-Encoding member '{}'",
                                        name, part
                                    ),
                                });
                            };

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
    // A qvalue may end at the point: `0*3DIGIT` admits no digits at all.
    #[case(Some("gzip;q=0."), false)]
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

    /// `Accept-Encoding = #( codings [ weight ] )`. A coding may carry a weight
    /// and nothing else, so every `param=` case below is malformed however
    /// well formed the pair looks — which is what these cases used to assert
    /// the opposite of. A well-formed parameter of a kind the field has no room
    /// for is still a defect; it just is not a *parameter* defect.
    #[rstest]
    #[case(Some("gzip;param=token"), true)]
    #[case(Some("gzip;param=\"ok\""), true)]
    #[case(Some("gzip;param=\"a;b\""), true)]
    #[case(Some("gzip;param=bad value"), true)]
    #[case(Some("gzip;param=\"unterminated"), true)]
    #[case(Some("gzip;#=1"), true)]
    #[case(Some("*;param=token"), true)]
    #[case(Some("gzip;param=\"a\\\"b\""), true)]
    // `weight` brackets nothing, so a `;` with no weight after it is a
    // separator introducing something that is not there.
    #[case(Some("gzip;"), true)]
    #[case(Some("gzip; ;q=0.8"), true)]
    #[case(Some("gzip;param"), true)]
    #[case(Some("gzip;bad name=1"), true)]
    #[case(Some("gzip;q=1.0000, br;q=1.0"), true)]
    #[case(Some("gzip;q=1.0000, x!bad;q=0.5"), true)]
    #[case(Some("gzip@;q=0.5"), true)]
    #[case(Some("gzip;param=bad@val"), true)]
    // A member that is all weight and no coding: `codings` is not optional, and
    // a token is one or more characters — which a scan for an *invalid*
    // character can never notice.
    #[case(Some(";q=0.5"), true)]
    // At most one weight; `[ weight ]` is singular.
    #[case(Some("gzip;q=0.5;q=0.8"), true)]
    // The forms the grammar does produce, including the RFC's own examples.
    #[case(Some("compress, gzip"), false)]
    #[case(Some("compress;q=0.5, gzip;q=1.0"), false)]
    #[case(Some("gzip;q=1.0, identity; q=0.5, *;q=0"), false)]
    #[case(Some("*"), false)]
    // An empty field value is legal, and §12.5.3 gives it a meaning: no content
    // coding is wanted at all.
    #[case(Some(""), false)]
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
