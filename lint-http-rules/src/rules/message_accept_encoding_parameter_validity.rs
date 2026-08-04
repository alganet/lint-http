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

    // Both, because both directions carry the field with a meaning: a request
    // states what codings a response may use, a response what the resource was
    // willing to accept. The label said `Client` while §12.5.3 defines two
    // readings and gives them the same syntax.
    // cite(RFC 9110 § 12.5.3): "When sent by a user agent in a request, Accept-Encoding indicates the content codings acceptable in a response."
    // cite(RFC 9110 § 12.5.3): "When the Accept-Encoding header field is present in a response, it indicates what content codings the resource was willing to accept in the associated request."
    // cite(RFC 9110 § 12.5.3): "The field value is evaluated the same way as in a request."
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

        // The production the whole rule is a reading of. Two things about it
        // decide almost every branch below: a member is a coding and at most
        // one weight, and `codings` has exactly three alternatives.
        // cite(RFC 9110 § 12.5.3): "Accept-Encoding  = #( codings [ weight ] ) codings          = content-coding / "identity" / "*""
        // cite(RFC 9110 § 12.4.2): "weight = OWS ";" OWS "q=" qvalue"
        let check_all = |headers: &hyper::HeaderMap| -> Option<Violation> {
            for hv in headers.get_all("accept-encoding").iter() {
                if let Ok(val) = hv.to_str() {
                    // A comma split with no regard for quoting, which is
                    // correct here rather than merely tolerable: nothing in
                    // this field's grammar is a quoted-string, so there is no
                    // quoted comma for a quote-aware splitter to protect. An
                    // empty field value yields no members and no finding, which
                    // is right — §12.5.3 gives that value a meaning of its own.
                    // cite(RFC 9110 § 12.5.3): "An Accept-Encoding header field with a field value that is empty implies that the user agent does not want any content coding in response."
                    // cite(RFC 9110 § 5.6.1.2): "#element => [ element ] *( OWS "," OWS [ element ] )"
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
                            //
                            // The asterisk is exempted from the token check
                            // because it is one of the three alternatives, not a
                            // coding name; "identity" needs no exemption, being
                            // a token like any other.
                            // cite(RFC 9110 § 8.4.1): "content-coding   = token"
                            // cite(RFC 9110 § 12.5.3): "The asterisk "*" symbol in an Accept-Encoding field matches any available content coding not explicitly listed in the field."
                            // cite(RFC 9110 § 12.5.3): "An "identity" token is used as a synonym for "no encoding" in order to communicate when no encoding is preferred."
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
                                if let Some(c) =
                                    crate::helpers::token::find_invalid_token_char(primary)
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
                            //
                            // The weight is a MAY, so its absence is never a
                            // finding; what is a finding is anything else in
                            // its place, or two of it.
                            // cite(RFC 9110 § 12.5.3): "Each codings value MAY be given an associated quality value (weight) representing the preference for that encoding, as defined in Section 12.4.2."
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

                                // The name is matched without regard to case
                                // because §12.4.2 defines the parameter that
                                // way, and this is the only name the field
                                // admits.
                                // cite(RFC 9110 § 12.4.2): "The content negotiation fields defined by this specification use a common parameter, named "q" (case-insensitive), to assign a relative "weight" to the preference for that associated kind of content."
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
                    // Reported rather than skipped, and this field is the reason.
                    // The rules audited alongside this one decode such a value
                    // instead, because `obs-text` is legal inside a quoted-string
                    // and refusing the value would hide findings elsewhere in it.
                    // There are no quoted-strings here: every part of an
                    // Accept-Encoding member is a `token` or the fixed text of a
                    // weight, so an octet `to_str` refuses cannot be a legal part
                    // of this field whatever else the value contains.
                    return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message:
                        "Accept-Encoding contains an octet no part of this field's grammar admits"
                            .into(),
                });
                }
            }
            None
        };

        // A response's Accept-Encoding is not a stray request field: §12.5.3
        // gives it a meaning of its own — what the resource was willing to
        // accept — and says its value is evaluated the same way. Only the
        // request was ever read, so a malformed one in a 415 response, which is
        // where the field most often appears, went unchecked.
        if let Some(v) = check_all(&tx.request.headers) {
            return Some(v);
        }
        if let Some(resp) = &tx.response {
            if let Some(v) = check_all(&resp.headers) {
                return Some(v);
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Accept-Encoding Parameter Validity")
    }

    fn description(&self) -> &'static str {
        "Check that an `Accept-Encoding` header reads as `#( codings [ weight ] )`: each member a content coding, the literal `identity`, or the literal `*`, optionally followed by a weight.\n\n**The rule's name is a little wrong, and the reason is the point.** `Accept-Encoding` has no parameter list. A coding may carry a `weight` — `OWS \";\" OWS \"q=\" qvalue` — and nothing else, so there is no `name=value` grammar here to be well formed. What this rule checks is that nothing other than a weight appears: `gzip;charset=utf-8` and `gzip;foo=\"a;b\"` are reported, however well formed the pair looks in isolation, because no derivation of this field produces them.\n\n**Three consequences of the same reading.** `weight` brackets nothing, so `gzip;` is a separator introducing a weight that is not there. `[ weight ]` is singular, so `gzip;q=0.5;q=0.8` is two of something there may be at most one of. And `codings` is not optional, so `;q=0.5` is a member with no coding.\n\n**A weight is a MAY**, so its absence is never reported; `gzip, br` is as conforming as `gzip;q=1.0, br;q=0.5`. When present it must be a `qvalue`: `0` to `1` with at most three digits after the point.\n\n**Both directions are read.** A request states what codings a response may use; a response, per §12.5.3, says what the resource was willing to accept — most often in a 415 (Unsupported Media Type), and evaluated the same way.\n\n**An empty field value is not reported.** §12.5.3 gives it a meaning of its own: the user agent wants no content coding at all.\n\n**An octet outside visible US-ASCII is reported** rather than skipped, unlike the neighbouring `Accept` rules. Those decode such a value because `obs-text` is legal inside a quoted-string; there are no quoted-strings here, so no octet `to_str` refuses can be a legal part of this field."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("12.5.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.3",
                note: "Accept-Encoding: `#( codings [ weight ] )` — the production that says a coding may carry a weight and nothing else. Also the three `codings` alternatives, the meaning of an empty field value, and the meaning of the field in a response",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("12.4.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.2",
                note: "Quality Values: the `weight` production this field admits, the `qvalue` its value must be, and the case-insensitive parameter name",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.4.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4.1",
                note: "Content Codings: `content-coding = token`, which is what the character check on each coding enforces",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.1.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.2",
                note: "Sender Requirements for lists: the bracketing that makes an empty list element something a recipient may ignore",
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
            Example {
                compliance: Compliance::Compliant,
                label: Some("(an empty value asks for no coding at all)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Encoding:",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a coding may carry a weight and nothing else)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip;charset=utf-8",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a weight there may be at most one of)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip;q=0.5;q=0.8",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a separator introducing a weight that is not there)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip;",
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

    /// Every published snippet is run through the rule, each NonCompliant one
    /// pinned to the finding it illustrates.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, Rule as _};
        let rule = MessageAcceptEncodingParameterValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let reasons: [(&str, &str); 6] = [
            ("gzip;q=1.0000", "Invalid qvalue"),
            ("gzip@;q=0.5", "Invalid token"),
            ("gzip;q=", "Invalid qvalue"),
            ("gzip;charset=utf-8", "is not a weight"),
            ("gzip;q=0.5;q=0.8", "More than one weight"),
            ("gzip;", "no weight after it"),
        ];

        for ex in rule.examples() {
            let pairs: Vec<(&str, &str)> = ex
                .snippet
                .lines()
                .filter(|l| !l.contains("HTTP/"))
                .map(|l| {
                    let (k, v) = l
                        .split_once(':')
                        .unwrap_or_else(|| panic!("not a header line: {l:?}"));
                    (k, v.trim())
                })
                .collect();
            let ae = pairs
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("accept-encoding"))
                .map(|(_, v)| *v)
                .unwrap_or_else(|| panic!("example has no Accept-Encoding: {:?}", ex.snippet));
            let mut tx = crate::test_helpers::make_test_transaction();
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&pairs);
            let found = rule.check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            );
            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule rejects its Compliant example {:?}: {found:?}",
                    ex.snippet
                ),
                Compliance::NonCompliant => {
                    let found = found.unwrap_or_else(|| {
                        panic!("rule accepts its NonCompliant example {:?}", ex.snippet)
                    });
                    let expected = *reasons
                        .iter()
                        .find(|(v, _)| *v == ae)
                        .map(|(_, reason)| reason)
                        .unwrap_or_else(|| {
                            panic!("NonCompliant example {ae:?} has no expected finding here")
                        });
                    assert!(
                        found.message.contains(expected),
                        "NonCompliant example {ae:?} should fail with {expected:?}: {found:?}"
                    );
                }
            }
        }
    }

    /// §12.5.3 gives a response's Accept-Encoding a meaning of its own — what
    /// the resource was willing to accept — and says its value is evaluated the
    /// same way as in a request. A 415 is where the field most often appears,
    /// and only the request was ever read.
    #[rstest]
    #[case("gzip;q=1.0000", true)]
    #[case("gzip;charset=utf-8", true)]
    #[case("gzip, br;q=0.5", false)]
    fn accept_encoding_in_a_response_is_read_too(
        #[case] value: &str,
        #[case] expect_violation: bool,
    ) {
        let rule = MessageAcceptEncodingParameterValidity;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(415, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept-encoding", value)]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(v.is_some(), expect_violation, "{value:?} -> {v:?}");
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
