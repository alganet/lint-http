// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct StatusCodeSemantics;

/// True when the field's combined value carries at least one non-empty list element.
///
/// Both fields this rule reads are `#challenge`, and both MUSTs are written about a
/// *challenge* rather than about a field line — so presence of the line is only half
/// of each requirement. An element that holds nothing but optional whitespace is not
/// a challenge and does not count:
/// cite(RFC 9110 § 5.6.1.2): "Empty elements do not contribute to the count of elements present."
///
/// The lines are deliberately not joined first, and for this one question they need
/// not be: the combined value is the field line values concatenated with a comma
/// between them
/// cite(RFC 9110 § 5.2): "When a field name is repeated within a section, its combined field value consists of the list of corresponding field line values within that section, concatenated in order, with each field line value separated by a comma."
/// — and the character the join inserts is itself an element delimiter, so the
/// combined value carries a non-empty element exactly when some single line does.
/// Several lines is the expected shape for these two fields, not an edge case:
/// cite(RFC 9110 § 11.6.1): "Furthermore, the header field itself can occur multiple times."
///
/// That last sentence is written in `WWW-Authenticate`'s section, and it reaches
/// `Proxy-Authenticate` because §11.7.1 sends it there rather than because the two
/// fields look alike:
/// cite(RFC 9110 § 11.7.1): "Note that the parsing considerations for WWW-Authenticate apply to this header field as well; see Section 11.6.1 for details."
///
/// The octets are read undecoded. Whether an element is a well-formed `challenge`
/// belongs to `www_authenticate_challenge_syntax`; whether one exists at all
/// is answerable without knowing what the bytes spell, and `to_str` would answer
/// "no challenge" for a value it merely cannot decode.
fn carries_a_challenge(headers: &hyper::HeaderMap, name: &str) -> bool {
    headers.get_all(name).iter().any(|hv| {
        hv.as_bytes()
            .iter()
            .any(|b| !matches!(b, b' ' | b'\t' | b','))
    })
}

impl Rule for StatusCodeSemantics {
    fn id(&self) -> &'static str {
        "status_code_semantics"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
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
            // This rule reads the response and never the request, and the two fields say
            // so differently. `WWW-Authenticate` is called a response header field in its
            // definition's first words; `Proxy-Authenticate`'s definition never uses the
            // word, and what puts that field in a response is the sentence after it,
            // which names the response it is sent in.
            // cite(RFC 9110 § 11.6.1): "The "WWW-Authenticate" response header field indicates the authentication scheme(s) and parameters applicable to the target resource."
            // cite(RFC 9110 § 11.7.1): "The "Proxy-Authenticate" header field consists of at least one challenge that indicates the authentication scheme(s) and parameters applicable to the proxy for this request."
            // cite(RFC 9110 § 11.7.1): "A proxy MUST send at least one Proxy-Authenticate header field in each 407 (Proxy Authentication Required) response that it generates."
            let resp = tx.response.as_ref()?;
            let status = resp.status;

            // cite(RFC 9110 § 15.5.2): "The 401 (Unauthorized) status code indicates that the request has not been applied because it lacks valid authentication credentials for the target resource."
            if status == 401 {
                // The MUST is on the server that *generated* the 401 and what this rule
                // has is the response as it arrived, several hops later. The two are the
                // same question for this field: an intermediary is forbidden from
                // touching it, so a field absent here was absent there — unless some hop
                // is violating a MUST NOT of its own, which this rule cannot see and
                // would report against the origin.
                // cite(RFC 9110 § 11.6.1): "A proxy forwarding a response MUST NOT modify any WWW-Authenticate header fields in that response."
                // cite(RFC 9110 § 15.5.2): "The server generating a 401 response MUST send a WWW-Authenticate header field (Section 11.6.1) containing at least one challenge applicable to the target resource."
                if !resp.headers.contains_key("www-authenticate") {
                    return Some(
                        self.violation(
                            ctx.severity,
                            "401 Unauthorized response carries no WWW-Authenticate field; a \
                                  server generating a 401 MUST send one containing at least one \
                                  challenge applicable to the target resource"
                                .into(),
                        ),
                    );
                }

                // "containing at least one challenge" is the other half of the same MUST,
                // and it is not a syntax question: the field's own grammar admits a value
                // with no challenge in it, so an empty `WWW-Authenticate:` is a conforming
                // field line and a 401 that violates its status definition. (Today
                // `www_authenticate_challenge_syntax` reports the same value as a
                // syntax error, which the `#` grammar does not support — that is a defect
                // in that rule, not the reason this check exists.)
                // cite(RFC 9110 § A): "WWW-Authenticate = [ challenge *( OWS "," OWS challenge ) ]"
                // cite(RFC 9110 § 15.5.2): "The server generating a 401 response MUST send a WWW-Authenticate header field (Section 11.6.1) containing at least one challenge applicable to the target resource."
                if !carries_a_challenge(&resp.headers, "www-authenticate") {
                    return Some(self.violation(ctx.severity, "401 Unauthorized response carries a WWW-Authenticate field with no \
                                  challenge in it (the value is empty, or every element of it is); a \
                                  server generating a 401 MUST send at least one challenge applicable \
                                  to the target resource"
                            .into()));
                }
            }

            // A `WWW-Authenticate` on any other status is **not** reported, and the field's
            // own definition is why: the permission is explicit and general, so a server
            // hinting that credentials would change the answer is doing what RFC 9110 says
            // it may. This rule used to report every such response, with a published
            // example and two tests asserting it.
            // cite(RFC 9110 § 11.6.1): "A server MAY generate a WWW-Authenticate header field in other response messages to indicate that supplying credentials (or different credentials) might affect the response."

            // cite(RFC 9110 § 15.5.8): "The 407 (Proxy Authentication Required) status code is similar to 401 (Unauthorized), but it indicates that the client needs to authenticate itself in order to use a proxy for this request."
            if status == 407 {
                // The 401's guarantee has no counterpart here: nothing forbids an
                // intermediary from touching this field, and its own definition says it
                // is addressed to one hop, so a proxy on the way is entitled to answer
                // for itself. The observed absence is still the only reading available,
                // and it is weaker evidence about the generator than the 401's.
                // cite(RFC 9110 § 11.7.1): "Unlike WWW-Authenticate, the Proxy-Authenticate header field applies only to the next outbound client on the response chain."
                // cite(RFC 9110 § 15.5.8): "The proxy MUST send a Proxy-Authenticate header field (Section 11.7.1) containing a challenge applicable to that proxy for the request."
                // cite(RFC 9110 § 11.7.1): "A proxy MUST send at least one Proxy-Authenticate header field in each 407 (Proxy Authentication Required) response that it generates."
                if !resp.headers.contains_key("proxy-authenticate") {
                    return Some(self.violation(ctx.severity, "407 Proxy Authentication Required response carries no \
                                  Proxy-Authenticate field; the proxy generating a 407 MUST send at \
                                  least one, containing a challenge applicable to that proxy for the \
                                  request"
                            .into()));
                }

                // Same shape as the 401 above: the grammar permits a value with no
                // challenge in it and the status definition does not.
                // cite(RFC 9110 § A): "Proxy-Authenticate = [ challenge *( OWS "," OWS challenge ) ]"
                // cite(RFC 9110 § 15.5.8): "The proxy MUST send a Proxy-Authenticate header field (Section 11.7.1) containing a challenge applicable to that proxy for the request."
                if !carries_a_challenge(&resp.headers, "proxy-authenticate") {
                    return Some(self.violation(ctx.severity, "407 Proxy Authentication Required response carries a \
                                  Proxy-Authenticate field with no challenge in it (the value is \
                                  empty, or every element of it is); the proxy generating a 407 MUST \
                                  send a challenge applicable to that proxy for the request"
                            .into()));
                }

                return None;
            }

            // No sentence makes this one a violation, and the asymmetry with
            // `WWW-Authenticate` is deliberate rather than drift: §11.6.1 spends a
            // sentence permitting its field on other responses and §11.7.1 spends none,
            // but a permission that was never written is not a prohibition either. What
            // §11.7.1 does say is that the field addresses the client that chose this
            // proxy — outside a 407 nothing tells that client what to do with the
            // challenge, which is an interoperability observation rather than a
            // requirement. So the finding is advisory, and `description()` says so where
            // an operator reads it.
            // cite(RFC 9110 § 11.7.1): "Unlike WWW-Authenticate, the Proxy-Authenticate header field applies only to the next outbound client on the response chain."
            if resp.headers.contains_key("proxy-authenticate") {
                return Some(self.violation(ctx.severity, format!(
                        "Proxy-Authenticate arrived on status {status}; RFC 9110 pairs this field \
                         with 407 Proxy Authentication Required, the one response a proxy MUST send \
                         it in. No requirement forbids it here — the field's definition puts no \
                         condition on the status code — so a client is simply not told what to do \
                         with the challenge. WWW-Authenticate is not reported this way: its own \
                         definition permits it on any response"
                    )));
            }

            None
        };
        Vec::from_iter(finding())
    }

    fn title(&self) -> Option<&'static str> {
        Some("Challenges the 401 and the 407 are defined by")
    }

    fn description(&self) -> &'static str {
        "Two status codes are defined in terms of a field the response has to carry, and this rule reports the responses that do not carry it — plus, advisorily, a `Proxy-Authenticate` arriving on any other status.\n\n- `401 Unauthorized` — a server generating one **MUST** send a `WWW-Authenticate` header field containing at least one challenge applicable to the target resource (RFC 9110 §15.5.2, §11.6.1)\n- `407 Proxy Authentication Required` — the proxy generating one **MUST** send at least one `Proxy-Authenticate` header field, containing a challenge applicable to that proxy for the request (RFC 9110 §15.5.8, §11.7.1)\n\nBoth MUSTs ask for a **challenge**, not for a field line, so a `401` carrying an empty `WWW-Authenticate:` is reported too. That case is not a syntax defect: both fields are defined as `#challenge`, a `#` list is permitted to hold no elements at all, and a recipient is required to accept the empty ones it does hold — so the value is well-formed, and what it fails is its status definition. Whether an element that *is* present is a well-formed challenge belongs to `www_authenticate_challenge_syntax`; this rule only asks whether one is there at all.\n\n**A `WWW-Authenticate` on any other status is not reported.** §11.6.1 says a server **MAY** generate one in other responses, to indicate that supplying credentials (or different credentials) might affect the response — so the field is permitted anywhere and a rule reporting it would be reporting a permission being used.\n\n**A `Proxy-Authenticate` outside a 407 is reported, and no requirement is violated by such a response.** §11.7.1 gives that field no matching permission, but it states no prohibition either; what it does say is that the field addresses the one client that chose this proxy, and outside a 407 nothing tells that client what to do with the challenge. The finding is advisory — configure the severity accordingly. The two fields are treated differently here on purpose, and the difference is one sentence in §11.6.1 that §11.7.1 does not have.\n\nThe response status and those two fields are the whole input — whether a challenge is there, never what it says. A 401 is measured from the response as it arrived rather than as it was generated, which §11.6.1 makes the same question by forbidding an intermediary from modifying the field; for the 407 no such sentence exists, and §11.7.1 addresses that field to a single hop, so an absence there is weaker evidence about the proxy that generated the status. The rule says nothing about `Authorization`, `Proxy-Authorization`, or the content of the response."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.5.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.2",
                note: "401 (Unauthorized) — the MUST for a `WWW-Authenticate` header field containing at least one challenge",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("11.6.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.1",
                note: "`WWW-Authenticate` — the field definition, the same MUST for a 401, and the MAY that permits the field on any other response (which is why this rule reports no such response)",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.5.8"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.8",
                note: "407 (Proxy Authentication Required) — the MUST for a `Proxy-Authenticate` header field containing a challenge applicable to that proxy",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("11.7.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-11.7.1",
                note: "`Proxy-Authenticate` — at least one field in each 407 the proxy generates, and the sentence limiting the field to the next outbound client, which is all that stands behind the advisory finding on other statuses",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.1.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.2",
                note: "Empty list elements do not contribute to the count of elements present — why `WWW-Authenticate: ,` carries no challenge",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15",
                note: "Status Codes — the part of the document both status definitions live in",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Basic realm=\"example\"\n\n{\"error\":\"unauthorized\"}",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 407 Proxy Authentication Required\nProxy-Authenticate: Basic realm=\"proxy\"\n",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— a server MAY hint that credentials would change the answer"),
                snippet: "HTTP/1.1 200 OK\nWWW-Authenticate: Basic realm=\"example\"\n\n{\"ok\":true}",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 401 Unauthorized\nContent-Type: application/json\n\n{\"error\":\"unauthorized\"}",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— the field line is there and the challenge is not"),
                snippet: "HTTP/1.1 401 Unauthorized\nWWW-Authenticate:",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 407 Proxy Authentication Required\nContent-Type: text/plain",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— advisory: no requirement is violated by this response"),
                snippet: "HTTP/1.1 200 OK\nProxy-Authenticate: Basic realm=\"proxy\"",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &StatusCodeSemantics;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn judge(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        let rule = StatusCodeSemantics;
        crate::test_helpers::run_rule(
            &rule,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    fn response_with(
        status: u16,
        headers: &[(&str, &str)],
    ) -> crate::http_transaction::HttpTransaction {
        crate::test_helpers::make_test_transaction_with_response(status, headers)
    }

    #[test]
    fn id_and_scope() {
        let r = StatusCodeSemantics;
        assert_eq!(r.id(), "status_code_semantics");
        assert_eq!(r.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn missing_www_on_401_reports_violation() {
        let v = judge(&response_with(401, &[])).expect("expected violation");
        assert!(
            v.message.contains("carries no WWW-Authenticate"),
            "{}",
            v.message
        );
    }

    #[test]
    fn missing_proxy_on_407_reports_violation() {
        let v = judge(&response_with(407, &[])).expect("expected violation");
        assert!(
            v.message.contains("carries no Proxy-Authenticate"),
            "{}",
            v.message
        );
    }

    #[test]
    fn www_on_401_is_ok() {
        assert!(judge(&response_with(
            401,
            &[("www-authenticate", "Basic realm=\"x\"")]
        ))
        .is_none());
    }

    /// §11.6.1 permits the field on any response, in as many words. This rule
    /// reported every such response until 2026-07-31, with a published example.
    #[test]
    fn www_on_non_401_is_permitted() {
        assert!(judge(&response_with(
            200,
            &[("www-authenticate", "Basic realm=\"x\"")]
        ))
        .is_none());
        assert!(judge(&response_with(403, &[("www-authenticate", "Bearer")])).is_none());
    }

    /// The same permission, on the status whose own field is present too.
    #[test]
    fn www_alongside_proxy_on_407_is_permitted() {
        let tx = response_with(
            407,
            &[
                ("proxy-authenticate", "Basic realm=\"proxy\""),
                ("www-authenticate", "Basic realm=\"x\""),
            ],
        );
        assert!(judge(&tx).is_none());
    }

    #[test]
    fn header_name_case_insensitive_is_accepted() {
        // §5.1: field names are case-insensitive, and the header map matches that.
        let tx = response_with(401, &[("WWW-AUTHENTICATE", "Basic realm=\"x\"")]);
        assert!(judge(&tx).is_none());
    }

    /// An undecodable value is a value: `carries_a_challenge` reads octets, so the
    /// rule does not confuse "cannot be decoded" with "carries no challenge".
    #[test]
    fn non_utf8_header_value_counts_as_a_challenge() {
        let mut tx = response_with(401, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "www-authenticate",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;
        assert!(
            judge(&tx).is_none(),
            "non-UTF8 header value should still be treated as a challenge"
        );
    }

    /// The second half of §15.5.2's MUST. `WWW-Authenticate = #challenge` admits an
    /// empty value, so no syntax rule reports these and only the status definition
    /// asks for more.
    #[rstest::rstest]
    #[case("")]
    #[case(" ")]
    #[case(",")]
    #[case(", ,")]
    fn empty_www_value_on_401_reports_no_challenge(#[case] value: &str) {
        let v = judge(&response_with(401, &[("www-authenticate", value)]))
            .unwrap_or_else(|| panic!("expected violation for {value:?}"));
        assert!(
            v.message
                .contains("WWW-Authenticate field with no challenge in it"),
            "{}",
            v.message
        );
    }

    #[rstest::rstest]
    #[case("")]
    #[case(",,")]
    fn empty_proxy_value_on_407_reports_no_challenge(#[case] value: &str) {
        let v = judge(&response_with(407, &[("proxy-authenticate", value)]))
            .unwrap_or_else(|| panic!("expected violation for {value:?}"));
        assert!(
            v.message
                .contains("Proxy-Authenticate field with no challenge in it"),
            "{}",
            v.message
        );
    }

    /// §5.2's combined value is what the MUST is about, and one line of it holding a
    /// challenge is enough — including when the empty line comes first.
    #[test]
    fn a_challenge_on_the_second_field_line_satisfies_the_must() {
        let tx = response_with(
            401,
            &[
                ("www-authenticate", ""),
                ("www-authenticate", "Basic realm=\"x\""),
            ],
        );
        assert!(judge(&tx).is_none());
    }

    #[test]
    fn proxy_authenticate_on_non_407_is_advisory_but_reported() {
        let v = judge(&response_with(
            200,
            &[("proxy-authenticate", "Basic realm=\"x\"")],
        ))
        .expect("expected violation");
        assert!(v.message.contains("status 200"), "{}", v.message);
        assert!(
            v.message.contains("No requirement forbids it here"),
            "{}",
            v.message
        );
    }

    /// A 401 carrying the *proxy* field and not its own reaches the 401 branch first.
    /// The message says which of the rule's findings this is; the old test accepted
    /// either one and so asserted only that something fired.
    #[test]
    fn a_401_missing_its_own_field_is_reported_before_the_advisory_one() {
        let tx = response_with(401, &[("proxy-authenticate", "Basic realm=\"proxy\"")]);
        let v = judge(&tx).expect("expected violation");
        assert!(
            v.message.contains("carries no WWW-Authenticate"),
            "{}",
            v.message
        );
    }

    /// ... and once the 401 carries its own challenge, the advisory finding is what
    /// is left to report.
    #[test]
    fn a_401_carrying_both_fields_reports_the_advisory_finding() {
        let tx = response_with(
            401,
            &[
                ("www-authenticate", "Basic realm=\"x\""),
                ("proxy-authenticate", "Basic realm=\"proxy\""),
            ],
        );
        let v = judge(&tx).expect("expected violation");
        assert!(v.message.contains("status 401"), "{}", v.message);
        assert!(
            v.message.contains("Proxy-Authenticate arrived"),
            "{}",
            v.message
        );
    }

    #[test]
    fn a_response_with_neither_field_is_not_reported() {
        assert!(judge(&response_with(200, &[("content-type", "text/plain")])).is_none());
        assert!(judge(&response_with(500, &[])).is_none());
    }

    /// Every published snippet is run through the rule, including the two whose
    /// labels are claims about which verdict they get.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, Rule as _};
        let rule = StatusCodeSemantics;

        for ex in rule.examples() {
            let mut status = None;
            let mut pairs: Vec<(&str, &str)> = Vec::new();
            for (i, line) in ex.snippet.lines().enumerate() {
                if i == 0 {
                    let code = line
                        .strip_prefix("HTTP/1.1 ")
                        .and_then(|rest| rest.split_whitespace().next())
                        .and_then(|code| code.parse::<u16>().ok())
                        .unwrap_or_else(|| {
                            panic!("the first line of an example is its status line: {line:?}")
                        });
                    status = Some(code);
                    continue;
                }
                // The blank line ends the field section; whatever follows is content,
                // which this rule does not read.
                if line.is_empty() {
                    break;
                }
                let (name, value) = line.split_once(':').unwrap_or_else(|| {
                    panic!("example header line is not `Name: value`: {line:?}")
                });
                pairs.push((name, value.trim()));
            }
            let status = status.expect("example has a status line");

            let tx = crate::test_helpers::make_test_transaction_with_response(status, &pairs);
            let v = judge(&tx);
            match ex.compliance {
                Compliance::Compliant => assert!(v.is_none(), "{}: {v:?}", ex.snippet),
                Compliance::NonCompliant => assert!(v.is_some(), "{}", ex.snippet),
            }
        }
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["status_code_semantics"]);
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
