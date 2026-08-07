// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ClientAcceptEncodingPresent;

impl Rule for ClientAcceptEncodingPresent {
    fn id(&self) -> &'static str {
        "client_accept_encoding_present"
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

        // A CONNECT does not ask for a representation, so there is no response
        // content for a content coding to apply to. This is the method's own
        // semantics rather than a guess about the status it will get back:
        // CONNECT asks for a tunnel, and on success everything after the
        // response header section is opaque forwarded data.
        // cite(RFC 9110 § 9.3.6): "The CONNECT method requests that the recipient establish a tunnel to the destination origin server identified by the request target and, if successful, thereafter restrict its behavior to blind forwarding of data, in both directions, until the tunnel is closed."
        // cite(RFC 9110 § 9.3.6): "Any 2xx (Successful) response indicates that the sender (and all inbound proxies) will switch to tunnel mode immediately after the response header section; data received after that header section is from the server identified by the request target."
        //
        // Advising a client to negotiate content codings for a tunnel is noise,
        // and on a proxy it is noise on every CONNECT that passes through.
        if tx.request.method.eq_ignore_ascii_case("CONNECT") {
            return None;
        }

        // Nothing requires a client to send this field, so the rule is advice
        // throughout. What the advice *was* is the problem: the comment here
        // said the absence means "identity only" by default. § 12.5.3 says the
        // opposite, in the first of the three rules a server tests against.
        // cite(RFC 9110 § 12.5.3): "When sent by a user agent in a request, Accept-Encoding indicates the content codings acceptable in a response."
        // cite(RFC 9110 § 12.5.3): "If no Accept-Encoding header field is in the request, any content coding is considered acceptable by the user agent."
        // cite(RFC 9110 § 12.5.3): "Accept-Encoding = #( codings [ weight ] )"
        //
        // Absence is the *most permissive* state there is -- every coding is
        // acceptable, and a server that compresses anyway conforms. The
        // "identity only" reading belongs to a different value entirely: the
        // field present and empty.
        // cite(RFC 9110 § 12.5.3): "An Accept-Encoding header field with a field value that is empty implies that the user agent does not want any content coding in response."
        //
        // So the rule reported the permissive case on a rationale that
        // described the refusing one, and passed the refusing one in silence.
        // Both are reported now, and they are not the same finding.
        //
        // A member that is empty is not an element, so a value of `,` lists no
        // codings and reads the same way as one with nothing in it at all.
        // cite(RFC 9110 § 5.6.1.2): "Empty elements do not contribute to the count of elements present."
        let mut present = false;
        let mut any_coding = false;
        for hv in tx.request.headers.get_all("accept-encoding").iter() {
            present = true;
            let val = String::from_utf8_lossy(hv.as_bytes());
            if crate::helpers::headers::parse_list_header(&val)
                .next()
                .is_some()
            {
                any_coding = true;
            }
        }

        if !present {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Request expresses no content-coding preference (no Accept-Encoding \
                          header); any coding is acceptable, but most servers will not compress \
                          without an explicit signal"
                    .into(),
            });
        }

        if !any_coding {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Request declines all content codings (empty Accept-Encoding header)"
                    .into(),
            });
        }

        // Anything that lists a coding stops here, including the values that
        // refuse everything by *weight* rather than by omission. § 12.5.3's
        // second rule makes `*;q=0` -- or `identity;q=0` without a more
        // specific entry -- exclude even the unencoded representation, which is
        // a stronger refusal than an empty field. It is deliberately not
        // reported: that is a judgement about acceptability computed from
        // qvalues, not about whether a preference was expressed, and this rule
        // is the latter. Recorded so the omission reads as a decision.
        // cite(RFC 9110 § 12.5.3): "If the representation has no content coding, then it is acceptable by default unless specifically excluded by the Accept-Encoding header field stating either "identity;q=0" or "*;q=0" without a more specific entry for "identity"."
        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Client Accept-Encoding Present")
    }

    fn description(&self) -> &'static str {
        "Advice, not conformance: nothing in HTTP requires a client to send `Accept-Encoding`. The rule reports the two request shapes that will not receive compressed content, and they are different findings.\n\n**No `Accept-Encoding` at all.** RFC 9110 §12.5.3 is explicit that this is the *most permissive* state, not the least: \"If no Accept-Encoding header field is in the request, any content coding is considered acceptable by the user agent.\" A server that compresses anyway is conforming. It is still worth reporting, but on honest ground — in practice most deployed servers will not compress without an explicit signal, and that is a fact about servers rather than about the protocol. This rule used to say the opposite, describing absence as meaning \"identity only\".\n\n**An empty `Accept-Encoding`.** This is the value that means what absence was being blamed for: \"An Accept-Encoding header field with a field value that is empty implies that the user agent does not want any content coding in response.\" It used to pass without a word. A value listing no members — `,` — reads the same way, since an empty element is not an element (§5.6.1.2).\n\n**`identity` is a preference, not a silence.** §12.5.3 calls it \"a synonym for 'no encoding'\", so a client that sends it has expressed exactly what this field is for and is not reported.\n\n**`CONNECT` is skipped.** It asks for a tunnel rather than a representation (§9.3.6), so no content coding applies to what comes back."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("12.5.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.3",
                note: "Accept-Encoding — the grammar, and the two sentences this rule had backwards: absence means every coding is acceptable, while an empty value means none is wanted",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("9.3.6"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6",
                note: "CONNECT — a tunnel rather than a representation, so nothing comes back for a content coding to apply to",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.1.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.2",
                note: "Why a field value of `,` lists no codings and reads as empty",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nAccept-Encoding: gzip, deflate, br\n",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(identity is a stated preference)"),
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nAccept-Encoding: identity\n",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(a tunnel has no representation to encode)"),
                snippet: "CONNECT server.example.com:443 HTTP/1.1\nHost: server.example.com\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(no preference expressed)"),
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nUser-Agent: my-script/1.0\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(every content coding declined)"),
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nAccept-Encoding: \n",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ClientAcceptEncodingPresent;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn req(headers: &[(&str, &str)]) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(headers);
        tx
    }

    fn run(tx: &crate::http_transaction::HttpTransaction) -> Option<crate::lint::Violation> {
        let rule = ClientAcceptEncodingPresent;
        rule.check_transaction(
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    /// Every published snippet is run through the rule, each NonCompliant one
    /// pinned to the finding it illustrates -- the two are easy to confuse,
    /// which is how the rule came to describe one and report the other.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, Rule as _};
        let rule = ClientAcceptEncodingPresent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let reasons: [(&str, &str); 2] = [
            (
                "(no preference expressed)",
                "expresses no content-coding preference",
            ),
            (
                "(every content coding declined)",
                "declines all content codings",
            ),
        ];

        for ex in rule.examples() {
            let mut lines = ex.snippet.lines();
            let start = lines.next().expect("empty snippet");
            let method = start.split_whitespace().next().expect("no method");
            let pairs: Vec<(&str, &str)> = lines
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    let (k, v) = l
                        .split_once(':')
                        .unwrap_or_else(|| panic!("not a header line: {l:?}"));
                    (k, v.trim())
                })
                .collect();

            let mut tx = req(&pairs);
            tx.request.method = method.to_string();
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
                    let label = ex.label.expect("NonCompliant examples are labelled here");
                    let expected = *reasons
                        .iter()
                        .find(|(l, _)| *l == label)
                        .map(|(_, r)| r)
                        .unwrap_or_else(|| panic!("no expected finding for {label:?}"));
                    assert!(
                        found.message.contains(expected),
                        "{label:?} should fail with {expected:?}: {found:?}"
                    );
                }
            }
        }
    }

    #[rstest]
    #[case(vec![("accept-encoding", "gzip")], None)]
    #[case(vec![("accept-encoding", "gzip, br")], None)]
    #[case(vec![("accept-encoding", "*")], None)]
    #[case(vec![("accept-encoding", "identity")], None)]
    #[case(vec![], Some("expresses no content-coding preference"))]
    #[case(vec![("user-agent", "my-script/1.0")], Some("expresses no content-coding preference"))]
    fn presence_and_absence(#[case] headers: Vec<(&str, &str)>, #[case] expected: Option<&str>) {
        let v = run(&req(&headers));
        match expected {
            None => assert!(v.is_none(), "{headers:?}: {v:?}"),
            Some(fragment) => assert!(
                v.is_some_and(|v| v.message.contains(fragment)),
                "{headers:?} should mention {fragment:?}"
            ),
        }
    }

    /// A value that refuses everything by weight still lists a coding, and this
    /// rule is about whether a preference was expressed, not about computing
    /// acceptability from qvalues. Pinned so the silence reads as a decision.
    #[rstest]
    #[case("*;q=0")]
    #[case("identity;q=0")]
    #[case("gzip;q=0")]
    fn a_refusal_by_weight_is_still_a_stated_preference(#[case] value: &str) {
        assert!(
            run(&req(&[("accept-encoding", value)])).is_none(),
            "{value:?}"
        );
    }

    /// A CONNECT asks for a tunnel, not a representation, so there is nothing
    /// for a content coding to apply to. On a proxy this fired on every one.
    #[rstest]
    #[case(vec![])]
    #[case(vec![("accept-encoding", "")])]
    fn connect_asks_for_no_representation(#[case] headers: Vec<(&str, &str)>) {
        let mut tx = req(&headers);
        tx.request.method = "CONNECT".into();
        assert!(run(&tx).is_none(), "{headers:?}");
    }

    /// And the exemption is the method's, not a general one.
    #[test]
    fn other_methods_are_still_advised() {
        for method in ["GET", "POST", "OPTIONS", "HEAD"] {
            let mut tx = req(&[]);
            tx.request.method = method.into();
            assert!(run(&tx).is_some(), "{method}");
        }
    }

    /// `identity` is a coding name, not an absence -- § 12.5.3 calls it "a
    /// synonym for 'no encoding'", which is a stated preference and exactly
    /// what this field is for.
    #[test]
    fn identity_is_a_preference_not_a_silence() {
        assert!(run(&req(&[("accept-encoding", "identity")])).is_none());
    }

    /// The empty field is the one that means what the rule's description used
    /// to claim absence meant. It used to pass in silence.
    #[rstest]
    #[case("")]
    #[case("   ")]
    // No member of this list is an element, so it lists no codings.
    #[case(",")]
    #[case(" , ")]
    fn an_empty_field_declines_every_coding(#[case] value: &str) {
        let v = run(&req(&[("accept-encoding", value)]));
        assert!(
            v.is_some_and(|v| v.message.contains("declines all content codings")),
            "{value:?} lists no codings"
        );
    }

    /// The two findings are distinct, because the states are.
    #[test]
    fn absence_and_refusal_are_different_findings() {
        let absent = run(&req(&[])).unwrap().message;
        let empty = run(&req(&[("accept-encoding", "")])).unwrap().message;
        assert_ne!(absent, empty);
        assert!(absent.contains("any coding is acceptable"));
        assert!(empty.contains("declines"));
    }

    #[test]
    fn scope_is_client() {
        let rule = ClientAcceptEncodingPresent;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }
}
