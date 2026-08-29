// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct AcceptLanguageWeightValid;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_12_5_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("12.5.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.4",
    note: "Accept-Language: `#( language-range [ weight ] )` — the production that says a range may carry a weight and nothing else. Note that, unlike Accept and Accept-Encoding, this section gives the field no meaning in a response",
};
const RFC_9110_12_4_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("12.4.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.2",
    note: "Quality Values: the `weight` production this field admits, the `qvalue` its value must be, and the case-insensitive parameter name",
};
const RFC_4647_2_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 4647",
    section: Some("2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc4647.html#section-2.1",
    note: "Basic Language Range: where `language-range` is defined, by reference from RFC 9110. Its syntax is `language_tag_syntax`'s subject, not this rule's",
};
const RFC_9110_5_6_1_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.1.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.2",
    note: "Sender Requirements for lists: the bracketing that makes an empty list element something a recipient may ignore",
};

impl Rule for AcceptLanguageWeightValid {
    fn id(&self) -> &'static str {
        "accept_language_weight_valid"
    }

    // `Both` describes what the code reads, not a second meaning the spec
    // gives the field. This is the asymmetry worth noticing: §12.5.1 and
    // §12.5.3 each say what Accept and Accept-Encoding mean *when sent by a
    // server in a response*, and §12.5.4 says no such thing about
    // Accept-Language — it defines a request field and stops. A response
    // carrying one is outside what RFC 9110 describes, so the response arm
    // here reports syntax and claims nothing about meaning.
    // cite(RFC 9110 § 12.5.4): "The "Accept-Language" header field can be used by user agents to indicate the set of natural languages that are preferred in the response."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            // The production the rule is a reading of. A member is a range and at
            // most one weight; nothing else derives from it.
            // cite(RFC 9110 § 12.5.4): "Accept-Language = #( language-range [ weight ] )"
            // cite(RFC 9110 § 12.4.2): "weight = OWS ";" OWS "q=" qvalue"
            let validate_value = |hdr_value: &str| -> Option<Violation> {
                // A comma split with no regard for quoting, which is right rather
                // than merely tolerable: nothing in this grammar is a
                // quoted-string, so there is no quoted comma to protect. Empty list
                // elements are skipped, which §5.6.1.2 permits a recipient to do.
                // cite(RFC 9110 § 5.6.1.2): "#element => [ element ] *( OWS "," OWS [ element ] )"
                for member in crate::helpers::list::list_members(hdr_value) {
                    // Each member: language-range [; params]
                    let mut iter = member.split(';').map(|s| s.trim());
                    // The language-range itself is `language_tag_syntax`'s
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
                    //
                    // The weight is optional — "can be given" — so its absence is
                    // never a finding. What is a finding is something else in its
                    // place, or two of it.
                    // cite(RFC 9110 § 12.5.4): "Each language-range can be given an associated quality value representing an estimate of the user's preference for the languages specified by that range, as defined in Section 12.4.2."
                    let mut weight_seen = false;
                    for param in iter {
                        // Not skipped as an empty parameter slot: there are no
                        // parameter slots, and `weight` brackets nothing, so a `;`
                        // with nothing after it introduces a weight that is absent.
                        if param.is_empty() {
                            return Some(self.violation(
                                ctx.severity,
                                format!(
                                    "Accept-Language member '{}' has a ';' with no weight after it",
                                    member
                                ),
                            ));
                        }
                        // Matched without regard to case because §12.4.2 defines
                        // the parameter that way, and this is the only name the
                        // field admits.
                        // cite(RFC 9110 § 12.4.2): "The content negotiation fields defined by this specification use a common parameter, named "q" (case-insensitive), to assign a relative "weight" to the preference for that associated kind of content."
                        let mut nv = param.splitn(2, '=').map(|s| s.trim());
                        let name = nv.next().unwrap();
                        let val_opt = nv.next();

                        if !name.eq_ignore_ascii_case("q") {
                            return Some(self.cited(&RFC_9110_12_4_2, ctx.severity, format!(
                                    "'{}' is not a weight, and a weight is the only thing an Accept-Language range may carry (member '{}')",
                                    param, member
                                )));
                        }
                        if weight_seen {
                            return Some(self.violation(
                                ctx.severity,
                                format!(
                                    "More than one weight in Accept-Language member '{}'",
                                    member
                                ),
                            ));
                        }
                        weight_seen = true;

                        let Some(val) = val_opt else {
                            return Some(self.violation(ctx.severity, format!(
                                    "Missing parameter value for '{}' in Accept-Language member '{}'",
                                    name, member
                                )));
                        };

                        // cite(RFC 9110 § 12.4.2): "qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )"
                        if !crate::helpers::headers::valid_qvalue(val) {
                            return Some(self.cited(
                                &RFC_9110_12_4_2,
                                ctx.severity,
                                format!(
                                    "Invalid qvalue '{}' in Accept-Language member '{}'",
                                    val, member
                                ),
                            ));
                        }
                    }
                }
                None
            };

            // Request
            for hv in tx.request.headers.get_all("accept-language").iter() {
                let Ok(val) = hv.to_str() else {
                    return Some(self.violation(ctx.severity, "Accept-Language contains an octet no part of this field's grammar admits"
                                .into()));
                };
                if let Some(v) = validate_value(val) {
                    return Some(v);
                }
            }

            // A response carrying Accept-Language is not something §12.5.4
            // describes, unlike its two siblings. The value is still read, because
            // a malformed one is malformed wherever it appears and a proxy does see
            // them echoed — but the finding is about syntax and says nothing about
            // what the field would mean here.
            if let Some(resp) = &tx.response {
                for hv in resp.headers.get_all("accept-language").iter() {
                    let Ok(val) = hv.to_str() else {
                        return Some(self.violation(ctx.severity, "Accept-Language contains an octet no part of this field's grammar admits"
                                    .into()));
                    };
                    if let Some(v) = validate_value(val) {
                        return Some(v);
                    }
                }
            }

            None
        };
        Vec::from_iter(finding())
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Accept-Language Weight Validity")
    }

    fn description(&self) -> &'static str {
        "Check that an `Accept-Language` header reads as `#( language-range [ weight ] )`: each member a language range, optionally followed by a weight whose value is a `qvalue` — `0` to `1` with at most three digits after the point.\n\n**There is no parameter list in this field.** A range may carry a weight and nothing else, so `en;charset=utf-8` is reported however well formed the pair looks in isolation. The rule used to check that parameter names were tokens and values were tokens or quoted-strings, which is the parameter grammar of a *different* kind of field; its own SpecRef note said it was following \"the same q/parameter validation semantics used across other headers in this project\".\n\n**Three consequences of the same reading.** `weight` brackets nothing, so `en;` and `en;;q=0.5` are separators introducing a weight that is not there. `[ weight ]` is singular, so `en;q=0.5;q=0.8` is two of it. And a weight is optional — `en, fr` is as conforming as `en;q=1, fr;q=0.8`.\n\n**The language range itself is not checked here.** That is `language_tag_syntax`'s subject: it reports an empty range, whitespace inside one, and an over-long subtag, and lets `*` through.\n\n**A response's Accept-Language is read, but the spec does not describe one.** This is the asymmetry worth knowing about: §12.5.1 and §12.5.3 each say what `Accept` and `Accept-Encoding` mean when a server sends them in a response, and §12.5.4 says no such thing — it defines a request field and stops. The value is still checked, because a malformed one is malformed wherever it appears, but the finding is about syntax and claims nothing about meaning.\n\n**Known leniency:** whitespace around the `=` is trimmed, so `q =0.5` is accepted, though `weight` spells the text as the literal `\"q=\"`. It can only miss a report, never invent one.\n\n**An octet outside visible US-ASCII is reported** rather than skipped: nothing in this grammar is a quoted-string, so no such octet can be a legal part of the field."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_12_5_4,
            RFC_9110_12_4_2,
            RFC_4647_2_1,
            RFC_9110_5_6_1_2,
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
                label: Some("(the wildcard range, and a weight is optional)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Language: *;q=0.5, en;q=0.7",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(RFC 9110 \u{a7}12.5.4's own example)"),
                snippet:
                    "GET / HTTP/1.1\nHost: example.com\nAccept-Language: da, en-gb;q=0.8, en;q=0.7",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a qvalue has at most three digits after the point)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Language: en;q=1.0000",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a range may carry a weight and nothing else)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Language: en;badparam=value",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a well-formed parameter the field still has no room for)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Language: en;foo=\"a\\\"b\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(no qvalue after the separator)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Language: en;q=",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a weight there may be at most one of)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept-Language: en;q=0.5;q=0.8",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &AcceptLanguageWeightValid;

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
        let rule = AcceptLanguageWeightValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_language_weight_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = al {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("accept-language", v)]);
        }

        let v = crate::test_helpers::run_rule(
            &rule,
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
        let rule = AcceptLanguageWeightValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("accept-language", bad);
        tx.request.headers = hm;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_language_weight_valid",
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn multiple_header_fields_are_checked() {
        let rule = AcceptLanguageWeightValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_language_weight_valid",
        ]);

        use hyper::header::HeaderValue;
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        headers.append("accept-language", HeaderValue::from_static("en, fr;q=0.5"));
        headers.append("accept-language", HeaderValue::from_static("zh;q=1.0000"));

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = headers;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn response_header_invalid_q_reports_violation() {
        let rule = AcceptLanguageWeightValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_language_weight_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept-language", "en;q=1.0000")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn response_non_utf8_header_value_is_violation() -> anyhow::Result<()> {
        let rule = AcceptLanguageWeightValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("accept-language", bad);
        tx.response.as_mut().unwrap().headers = hm;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_language_weight_valid",
        ]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    /// Every published snippet is run through the rule, each NonCompliant one
    /// pinned to the finding it illustrates. One Compliant example here was
    /// `en;foo="a\"b"` — published as conforming because the quoted-string is
    /// well formed, when the field has no room for the parameter at all. A
    /// premise this wrong reaches the docs as readily as it reaches the code.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, Rule as _};
        let rule = AcceptLanguageWeightValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let reasons: [(&str, &str); 5] = [
            ("en;q=1.0000", "Invalid qvalue"),
            ("en;badparam=value", "is not a weight"),
            ("en;foo=\"a\\\"b\"", "is not a weight"),
            ("en;q=", "Invalid qvalue"),
            ("en;q=0.5;q=0.8", "More than one weight"),
        ];

        for ex in rule.examples() {
            let pairs: Vec<(&str, &str)> = ex
                .snippet
                .lines()
                .filter(|l| !l.contains("HTTP/"))
                .map(|l| {
                    let (k, v) = l
                        .split_once(": ")
                        .unwrap_or_else(|| panic!("not a header line: {l:?}"));
                    (k, v)
                })
                .collect();
            let al = pairs
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("accept-language"))
                .map(|(_, v)| *v)
                .unwrap_or_else(|| panic!("example has no Accept-Language: {:?}", ex.snippet));
            let mut tx = crate::test_helpers::make_test_transaction();
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&pairs);
            let found = crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            );
            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule rejects its Compliant example {al:?}: {found:?}"
                ),
                Compliance::NonCompliant => {
                    let found = found
                        .unwrap_or_else(|| panic!("rule accepts its NonCompliant example {al:?}"));
                    let expected = *reasons
                        .iter()
                        .find(|(v, _)| *v == al)
                        .map(|(_, reason)| reason)
                        .unwrap_or_else(|| {
                            panic!("NonCompliant example {al:?} has no expected finding here")
                        });
                    assert!(
                        found.message.contains(expected),
                        "NonCompliant example {al:?} should fail with {expected:?}: {found:?}"
                    );
                }
            }
        }
    }

    /// `Accept-Language = #( language-range [ weight ] )` leaves no room for a
    /// `foo` parameter, well formed or not. These asserted the opposite: that a
    /// valid quoted-string value made the member acceptable, and that an
    /// invalid one was the reason to report it. The member is reported either
    /// way, and for the reason that holds for both.
    #[test]
    fn a_parameter_that_is_not_a_weight_is_reported_however_it_is_written() {
        let rule = AcceptLanguageWeightValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_language_weight_valid",
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
            let v = crate::test_helpers::run_rule(
                &rule,
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
        let rule = AcceptLanguageWeightValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_language_weight_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept-language", "en;b@d=1")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn param_without_value_reports_violation() {
        let rule = AcceptLanguageWeightValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_language_weight_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept-language", "en;param")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn wildcard_with_q_ok() {
        let rule = AcceptLanguageWeightValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_language_weight_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept-language", "*;q=0.5")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn uppercase_q_parameter_name_is_accepted() {
        let rule = AcceptLanguageWeightValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_language_weight_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept-language", "en;Q=0.5")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn multiple_header_fields_all_valid_no_violation() {
        let rule = AcceptLanguageWeightValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "accept_language_weight_valid",
        ]);

        use hyper::header::HeaderValue;
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        headers.append("accept-language", HeaderValue::from_static("en;q=1.0"));
        headers.append("accept-language", HeaderValue::from_static("fr;q=0.8"));

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = headers;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn scope_is_both() {
        let rule = AcceptLanguageWeightValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn message_and_id() {
        let rule = AcceptLanguageWeightValid;
        assert_eq!(rule.id(), "accept_language_weight_valid");
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "accept_language_weight_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
