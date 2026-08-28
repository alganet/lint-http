// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct RedirectStatusAndLocationValid;

/// Whether the status gives a `Location` field something to refer *to*.
///
/// §10.2.2 assigns the field a referent exactly twice, and the second assignment is
/// a **class**, not a list of codes: *"For 3xx (Redirection) responses"*. The rule
/// enumerated six of them (300, 301, 302, 303, 307, 308) — the ones whose own
/// definitions discuss redirection — so a `Location` on a `304`, on the deprecated
/// `305` and `306`, or on any 3xx nobody has registered was reported against a
/// sentence that names all of them. §15.4's permission is written about that last
/// case in as many words: a user agent may follow the field *"even if the specific
/// status code is not understood"*, which can only mean a 3xx it cannot name.
///
/// `304` stays in on purpose. §15.4.5's `SHOULD NOT` is about *representation
/// metadata* (§8), and `Location` is a response context field (§10.2) — so that
/// sentence does not reach it, and the class sentence does.
fn location_has_a_referent(status: u16) -> bool {
    // The 201's referent is written in the field's section and again in the status's
    // own definition. Neither asks for the field: they say what it means when it is
    // there. Whether a 201 *ought* to carry one is `post_creates_resource`'s
    // question, because the sentence that asks (§9.3.3) is about POST.
    //
    // This sentence names a **code** where the 3xx one below names a **class**, so the
    // exemption is one status wide and does not reach 200 or 202. The asymmetry is in
    // the two sentences, not in this rule's reading of them.
    // cite(RFC 9110 § 10.2.2): "For 201 (Created) responses, the Location value refers to the primary resource created by the request."
    // cite(RFC 9110 § 15.3.2): "The primary resource created by the request is identified by either a Location header field in the response or, if no Location header field is received, by the target URI."
    if status == 201 {
        return true;
    }

    // The whole 3xx class, because the sentence names the class. §15's requirement on
    // recipients is what makes that reading operative rather than generous: an
    // unrecognized 3xx *is* a 300 to every conforming client, so it carries 300's
    // relationship to the field.
    // cite(RFC 9110 § 10.2.2): "For 3xx (Redirection) responses, the Location value refers to the preferred target resource for automatically redirecting the request."
    // cite(RFC 9110 § 15): "However, a client MUST understand the class of any status code, as indicated by the first digit, and treat an unrecognized status code as being equivalent to the x00 status code of that class."
    // cite(RFC 9110 § 15.4): "If a Location header field (Section 10.2.2) is provided, the user agent MAY automatically redirect its request to the URI referenced by the Location field value, even if the specific status code is not understood."
    //
    // A status outside 100..599 falls out of this the way §15 asks: it is not in the
    // class, so it is reported, and the sentence below says a recipient treats it as a
    // 5xx — which gives the field no referent either. The status's own invalidity is
    // `status_code_valid_range`'s finding, not this one's. `resp.status` can
    // hold such a value because the `lint` subcommand deserializes it from a capture
    // file rather than reading it off a connection.
    // cite(RFC 9110 § 15): "A client that receives a response with an invalid status code SHOULD process the response as if it had a 5xx (Server Error) status code."
    (300..=399).contains(&status)
}

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_10_2_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("10.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.2",
    note: "`Location = URI-reference`; the value's referent is defined for 201 (Created) and for 3xx (Redirection) responses, and for no other status",
};
const RFC_9110_15_3_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15.3.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.2",
    note: "201 Created: the primary resource created is identified by a Location field or, if none is received, by the target URI — a description, not a request for the field",
};
const RFC_9110_15_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4",
    note: "Redirection 3xx: a provided Location may be followed automatically even where the user agent does not understand the specific status code",
};
const RFC_9110_15: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15",
    note: "An unrecognized status code is equivalent to the x00 of its class, which is what makes 3xx a class here rather than a list of six codes",
};

impl Rule for RedirectStatusAndLocationValid {
    fn id(&self) -> &'static str {
        "redirect_status_and_location_valid"
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
            // `Location` is a response context field, so the response is the message this
            // rule measures and a request-only transaction is out of its subject entirely.
            // cite(RFC 9110 § 10.2): "The response header fields below provide additional information about the response, beyond what is implied by the status code, including information about the server, about the target resource, or about related resources."
            let resp = tx.response.as_ref()?;

            // The status is read before the field because the status is the half of the
            // pair this rule can answer. The other half — the request method — matters to
            // the two rules that know it (`status_3xx_vs_request_method`,
            // `post_creates_resource`); nothing here varies with it.
            // cite(RFC 9110 § 10.2.2): "The type of relationship is defined by the combination of request method and status code semantics."
            let status = resp.status;
            if location_has_a_referent(status) {
                return None;
            }

            // Presence is the whole test. The value is not read, not decoded and not
            // joined: whether it is a usable `URI-reference`, whether it is empty, and
            // whether several field lines were sent are all
            // `location_header_uri_valid`'s questions, and none of them changes
            // whether the field was sent on a status that gives it no referent.
            //
            // The definitional sentence is the one this finding rests on, and it is
            // definitional: `Location` is *used in some responses*, and §10.2.2 names
            // which. It does not forbid the others, which is why the finding is advisory
            // and says so in `description()`.
            // cite(RFC 9110 § 10.2.2): "The "Location" header field is used in some responses to refer to a specific resource in relation to the response."
            resp.headers.get_all("location").iter().next()?;

            Some(self.cited(&RFC_9110_10_2_2, ctx.severity, format!(
                    "Response with status {status} carries a Location header field. RFC 9110 §10.2.2 \
                     defines what the value refers to on a 201 (Created) response and on a 3xx \
                     (Redirection) response, and on no other status — so on a {status} the field has \
                     no relationship to the response that the specification defines. No sentence in \
                     RFC 9110 forbids sending it."
                )))
        };
        Vec::from_iter(finding())
    }

    fn title(&self) -> Option<&'static str> {
        Some("A Location that refers to nothing")
    }

    fn description(&self) -> &'static str {
        "RFC 9110 §10.2.2 gives the `Location` header field a referent twice — the primary resource created, on a `201 Created`, and the preferred target resource to redirect to, on a `3xx (Redirection)` response. This rule reports a response on any other status that carries the field, because there the value refers to nothing the specification names.\n\n**This is advice, not a violation.** §10.2.2 says the field is *\"used in some responses\"* and then says which; it does not forbid the rest, and no other sentence in RFC 9110 does either. A `202 Accepted` carrying a `Location` for a status monitor is the common case — §15.3.3 asks the 202's *content* to point at that monitor, so the field is carrying a meaning by convention rather than by specification. What the finding buys is that the convention is visible.\n\n**The whole 3xx class is exempt, not a list of redirect codes.** The licensing sentence names `3xx (Redirection)` responses, so `304 Not Modified`, the deprecated `305 Use Proxy`, the reserved `306`, and any 3xx that is not registered at all are all exempt. §15.4 says a user agent MAY follow a provided `Location` *\"even if the specific status code is not understood\"*, and §15 requires a client to treat an unrecognized status as the `x00` of its class — so an unregistered 3xx is a `300` to every conforming recipient and carries the same relationship to the field. §15.4.5's `SHOULD NOT` on a 304 is about representation metadata (§8); `Location` is a response context field (§10.2) and is not reached by it.\n\n**Only presence is read.** Whether the value is a usable `URI-reference`, whether it is empty, and whether the response sent several `Location` field lines are `location_header_uri_valid`'s questions. A `301` or `302` that carries *no* `Location` is `location_on_redirect_present`'s. Whether a `201` ought to carry one is `post_creates_resource`'s, because the sentence that asks for it (§9.3.3) is about `POST`."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_10_2_2, RFC_9110_15_3_2, RFC_9110_15_4, RFC_9110_15]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nHello",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(redirect)"),
                snippet: "HTTP/1.1 302 Found\nLocation: /new",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(the referent is defined for the 3xx class)"),
                snippet: "HTTP/1.1 304 Not Modified\nETag: \"xyzzy\"\nLocation: /alternate",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(the resource the request created)"),
                snippet: "HTTP/1.1 201 Created\nLocation: /widgets/123",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nLocation: /unexpected",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a 202's status monitor is named by its content)"),
                snippet: "HTTP/1.1 202 Accepted\nLocation: /jobs/42",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &RedirectStatusAndLocationValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Every fixture is a response on some status, carrying the field or not.
    fn response_with(
        status: u16,
        location: Option<&str>,
    ) -> crate::http_transaction::HttpTransaction {
        let pairs: Vec<(&str, &str)> = location.into_iter().map(|v| ("location", v)).collect();
        crate::test_helpers::make_test_transaction_with_response(status, &pairs)
    }

    fn judge(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        let rule = RedirectStatusAndLocationValid;
        crate::test_helpers::run_rule(
            &rule,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    /// §10.2.2 names the 3xx *class*, so every code in it is exempt — including the
    /// four this rule used to report: 304, the deprecated 305, the reserved 306, and
    /// any 3xx that is not registered at all.
    #[rstest]
    #[case(300)]
    #[case(301)]
    #[case(302)]
    #[case(303)]
    #[case(304)]
    #[case(305)]
    #[case(306)]
    #[case(307)]
    #[case(308)]
    #[case(309)]
    #[case(350)]
    #[case(399)]
    fn no_status_in_the_3xx_class_is_reported(#[case] status: u16) {
        assert!(judge(&response_with(status, Some("/elsewhere"))).is_none());
        assert!(judge(&response_with(status, None)).is_none());
    }

    /// The other status with a referent, in both directions.
    #[rstest]
    #[case(201, None)]
    #[case(201, Some("/widgets/123"))]
    fn a_201_is_never_reported(#[case] status: u16, #[case] location: Option<&str>) {
        assert!(judge(&response_with(status, location)).is_none());
    }

    /// One code either side of the class boundary, so the range's ends are pinned —
    /// and one outside 100..599, which §15 says a recipient treats as a 5xx.
    #[rstest]
    #[case(299)]
    #[case(400)]
    #[case(600)]
    fn the_codes_bounding_the_class_are_reported(#[case] status: u16) {
        assert!(judge(&response_with(status, Some("/elsewhere"))).is_some());
    }

    /// A status with no referent, with and without the field.
    #[rstest]
    #[case(100, true)]
    #[case(200, true)]
    #[case(202, true)]
    #[case(204, true)]
    #[case(404, true)]
    #[case(500, true)]
    fn statuses_with_no_referent(#[case] status: u16, #[case] expect_violation: bool) {
        assert_eq!(
            judge(&response_with(status, Some("/somewhere"))).is_some(),
            expect_violation
        );
        assert!(judge(&response_with(status, None)).is_none());
    }

    /// Presence is the whole test, so an empty value is present. Whether an empty
    /// `Location` is a usable `URI-reference` is `location_header_uri_valid`'s
    /// question and reporting it here would say nothing about the value.
    #[test]
    fn an_empty_value_counts_as_present() {
        assert!(judge(&response_with(200, Some(""))).is_some());
    }

    /// The field is never decoded, so a value that is not UTF-8 is still a field that
    /// was sent. `get_header_str` would fold "absent" and "unreadable" together here.
    #[test]
    fn a_value_that_is_not_utf8_counts_as_present() {
        use hyper::header::HeaderValue;

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert("location", HeaderValue::from_bytes(b"\xff").unwrap());
        tx.response.as_mut().unwrap().headers = hm;

        assert!(judge(&tx).is_some());
    }

    /// Several field lines are still presence. §10.2.2's Note calls a multi-line
    /// `Location` an invalid message whose recovery is not interoperable — a finding
    /// about the field's syntax, which `location_header_uri_valid` owns.
    #[test]
    fn several_field_lines_count_as_present() {
        use hyper::header::HeaderValue;

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.append("location", HeaderValue::from_static("/first"));
        hm.append("location", HeaderValue::from_static("/second"));
        tx.response.as_mut().unwrap().headers = hm;

        assert!(judge(&tx).is_some());
    }

    #[test]
    fn no_response_is_ignored() {
        let rule = RedirectStatusAndLocationValid;
        let tx = crate::test_helpers::make_test_transaction();
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn id_and_scope() {
        let rule = RedirectStatusAndLocationValid;
        assert_eq!(rule.id(), "redirect_status_and_location_valid");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "redirect_status_and_location_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    /// The message is derived data: it names the status it was built from, twice, and
    /// says the finding rests on no prohibition. Both are claims about the rule.
    #[test]
    fn the_message_names_the_status_and_does_not_claim_a_violation() {
        let v = judge(&response_with(202, Some("/jobs/42"))).expect("expected violation");
        assert!(v.message.contains("status 202"), "{}", v.message);
        assert!(v.message.contains("on a 202"), "{}", v.message);
        assert!(
            v.message.contains("No sentence in RFC 9110 forbids"),
            "{}",
            v.message
        );
    }

    /// Every published snippet is run through the rule.
    #[test]
    fn published_examples_are_judged_by_this_rule() {
        use crate::rules::{Compliance, Rule as _};
        let rule = RedirectStatusAndLocationValid;

        for ex in rule.examples() {
            let mut status = None;
            let mut pairs: Vec<(&str, &str)> = Vec::new();
            for (i, line) in ex.snippet.lines().enumerate() {
                if line.is_empty() {
                    break;
                }
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
}
