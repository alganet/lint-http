// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Report a TRACE request that carries what § 9.3.8 forbids it to carry:
/// content, or a field holding the data that section names when it says a
/// loop-back must not be handed anything sensitive.
///
/// Both sentences address the client, and both are about the request, so
/// nothing here reads the response.
///
/// **What this rule used to check and no longer does.** It required a TRACE
/// response carrying content to use `message/http`. RFC 7231 § 4.3.8 did
/// require that; RFC 9110 does not, and says so twice — § 9.3.8 calls the
/// format one way to do so, and Appendix B.3 lists the removal among the
/// changes from RFC 7231 by name. The checks that rested on it are gone rather
/// than softened: a TRACE response in some other media type is a server taking
/// another way, not a server disobeying anything.
pub struct TraceMethodEcho;

/// The request fields § 9.3.8's example names, each with the sentence that says
/// the field is where that data travels.
///
/// The MUST NOT above them is about *data*, and no field says whether its value
/// is sensitive; these three are reported because the section itself names
/// their contents as the example of what a loop-back would disclose.
// cite(RFC 9110 § 9.3.8): "For example, it would be foolish for a user agent to send stored user credentials (Section 11) or cookies [COOKIE] in a TRACE request."
const SENSITIVE_FIELDS: [(&str, &str); 3] = [
    // cite(RFC 9110 § 11.6.2): "Its value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested."
    ("authorization", "Authorization"),
    // cite(RFC 9110 § 11.7.2): "Its value consists of credentials containing the authentication information of the client for the proxy and/or realm of the resource being requested."
    ("proxy-authorization", "Proxy-Authorization"),
    // cite(RFC 6265 § 4.2.1): "The user agent sends stored cookies to the origin server in the Cookie header."
    ("cookie", "Cookie"),
];

/// Whether the request carries `name` with anything in it.
///
/// § 9.3.8's MUST NOT is about a field *containing* sensitive data, so an empty
/// field line is outside it: there is nothing in it for the reflection to
/// disclose, and whichever rule owns that field's grammar reports the emptiness.
/// The whitespace comes off first because a field value never included it.
// cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace."
fn carries_a_value(headers: &hyper::HeaderMap, name: &str) -> bool {
    headers
        .get_all(name)
        .iter()
        .any(|v| v.as_bytes().iter().any(|b| !matches!(b, b' ' | b'\t')))
}

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_9_3_8: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("9.3.8"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.8",
    note: "TRACE — the two client `MUST NOT`s this rule reports, the example naming credentials and cookies, and the `SHOULD` to reflect the message, which is addressed to a recipient no message identifies",
};
const RFC_9110_9_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("9.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1",
    note: "The method token is case-sensitive, which is why `TRACE` is matched exactly and a lowercase `trace` is not a TRACE",
};
const RFC_9110_6_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("6.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-6.4",
    note: "Content — the octet stream left after framing is removed, which is what the content check measures instead of the presence of a framing field",
};
const RFC_9110_11_6_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("11.6.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.2",
    note: "`Authorization` carries the user agent's credentials; §11.7.2 says the same of `Proxy-Authorization` for a proxy",
};
const RFC_6265_4_2_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6265",
    section: Some("4.2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc6265.html#section-4.2.1",
    note: "`Cookie` is the field a user agent returns stored cookies in — the second kind of data §9.3.8's example names",
};
const RFC_9110_B_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("B.3"),
    // `appendix-B.3`, not `section-B.3`: an appendix anchors under
    // its own prefix, and the `section-` form scrolls nowhere.
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#appendix-B.3",
    note: "Changes from RFC 7231 — the normative requirement to use `message/http` in TRACE responses was removed, which is why this rule no longer asks for it",
};

impl Rule for TraceMethodEcho {
    fn id(&self) -> &'static str {
        "trace_method_echo"
    }

    /// Both sentences this rule enforces are requirements on the client, and a
    /// request that never drew a response has broken them or not already.
    // cite(RFC 9110 § 9.3.8): "A client MUST NOT send content in a TRACE request."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Matched exactly, never case-folded: `trace` is not the TRACE method,
        // and § 9.3.8 says nothing about it. A method this specification does
        // not define has no loop-back semantics for content to be measured
        // against.
        // cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
        if tx.request.method != "TRACE" {
            return Vec::new();
        }

        // Two requirements, and one request can break both. § 9.3.8 states
        // them as two sentences addressed to the same client: one about
        // sending content, one about the fields sent beside it. A TRACE
        // carrying a body *and* an Authorization header disobeys both, and
        // returning at the content said only half of it — the fix for the
        // half reported would have revealed the other.
        let mut out = Vec::new();

        // Content, not framing: the shared measurement reads § 6.4's octet
        // stream, so a chunked TRACE whose only chunk is the terminator carries
        // nothing to report, and a TRACE carrying an HTTP/2 DATA frame — which
        // declares no framing field at all — does.
        // cite(RFC 9110 § 9.3.8): "A client MUST NOT send content in a TRACE request."
        if let Some(evidence) = crate::helpers::content_length::content_evidence(
            &tx.request.headers,
            tx.request.body_length,
        ) {
            out.push(self.cited(&RFC_9110_9_3_8, ctx.severity, format!(
                        "TRACE request carries content ({evidence}); RFC 9110 § 9.3.8 says a client MUST NOT send content in a TRACE request"
                    )));
        }

        // The response is a loop-back of this request, so a field is disclosed
        // by having been sent — which is why the finding is about the request
        // and does not wait for the response to arrive.
        // cite(RFC 9110 § 9.3.8): "A client MUST NOT generate fields in a TRACE request containing sensitive data that might be disclosed by the response."
        let present: Vec<&str> = SENSITIVE_FIELDS
            .iter()
            .filter(|(lowercase, _)| carries_a_value(&tx.request.headers, lowercase))
            .map(|(_, name)| *name)
            .collect();

        // One finding for the whole set, not one per field: the sentence is
        // about the request the client generated, and every named field is
        // disclosed by the same loop-back. Naming them together is what an
        // operator acts on — this request must not have been sent as it was.
        if !present.is_empty() {
            out.push(self.violation(ctx.severity, format!(
                        "TRACE request carries {}; RFC 9110 § 9.3.8 says a client MUST NOT generate fields in a TRACE request containing sensitive data that might be disclosed by the response, and names credentials and cookies as its example",
                        present.join(", ")
                    )));
        }

        out
    }

    fn title(&self) -> Option<&'static str> {
        Some("Semantic TRACE Method Echo")
    }

    fn description(&self) -> &'static str {
        "Reports a TRACE request that carries content, and a TRACE request that carries one of the fields RFC 9110 §9.3.8 names when it forbids handing sensitive data to a loop-back. A TRACE asks the final recipient to \"reflect the message received, excluding some fields described below, back to the client as the content of a 200 (OK) response\", so what a TRACE request contains is what a TRACE response discloses.\n\n**Content.** §9.3.8: \"A client MUST NOT send content in a TRACE request.\" Content is §6.4's — the stream of octets after the header section, counted once framing has been taken off — so a `Transfer-Encoding: chunked` is not by itself content, a chunked TRACE whose only chunk is the terminator carries none, and over HTTP/2 and HTTP/3 content arrives with no framing field at all. Where a body was captured its octet count decides; otherwise the request's own `Content-Length` does — which leaves one case unmeasurable, a chunked request whose octets were not captured, since it declares no length to fall back to.\n\n**Sensitive fields.** §9.3.8 also says \"A client MUST NOT generate fields in a TRACE request containing sensitive data that might be disclosed by the response.\" Whether a value is sensitive is not something a message states, so this rule reports exactly the two kinds of data the section names as its example — stored user credentials (`Authorization`, `Proxy-Authorization`) and cookies (`Cookie`), and only where the field carries a value. Sensitive data under any other field name is not reported: the sentence leaves the class open, and a message does not say which of its values are sensitive.\n\n**Not checked: the response's media type.** RFC 7231 §4.3.8 required `message/http` on a TRACE response; RFC 9110 does not. §9.3.8 now calls that format one way to do so, and Appendix B.3 records the change — \"The normative requirement to use the \"message/http\" media type in TRACE responses has been removed.\" A TRACE response in another media type is reported by nothing here. A response that carries content with no `Content-Type` at all is `content_type_present`'s finding.\n\n**Not checked: whether the response reflected the request.** The reflection is a SHOULD addressed to \"the final recipient\" — the origin server, or the first server to receive a `Max-Forwards` of zero — and no field of a message says which recipient answered it."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_9_3_8,
            RFC_9110_9_1,
            RFC_9110_6_4,
            RFC_9110_11_6_2,
            RFC_6265_4_2_1,
            RFC_9110_B_3,
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("A loop-back carrying nothing to reflect"),
                snippet: "TRACE /diagnostics HTTP/1.1\nHost: example.com\nMax-Forwards: 3",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Content in a TRACE request"),
                snippet: "TRACE /diagnostics HTTP/1.1\nHost: example.com\nContent-Length: 4\n\nping",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Credentials and cookies, which the reflection would echo back"),
                snippet: "TRACE /diagnostics HTTP/1.1\nHost: example.com\nAuthorization: Basic dXNlcjpwYXNzd29yZA==\nCookie: session=8f1c2b",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &TraceMethodEcho;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// One constructor for every fixture, so `body_length` — the field that
    /// decides the content finding — is always stated rather than defaulted.
    fn make_tx(
        method: &str,
        headers: Vec<(&str, &str)>,
        body_length: Option<u64>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = method.to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&headers);
        tx.request.body_length = body_length;
        tx
    }

    fn check_all(tx: &crate::http_transaction::HttpTransaction) -> Vec<Violation> {
        let rule = TraceMethodEcho;
        crate::test_helpers::run_rule_all(
            &rule,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    /// § 9.3.8's two sentences are two findings, and one request can break
    /// both: this one carries a body *and* the credentials the section names as
    /// its example of what the loop-back would disclose. Reporting the content
    /// alone left the disclosure to be discovered by fixing the body.
    #[test]
    fn content_and_a_disclosed_field_are_two_findings() {
        let all = check_all(&make_tx(
            "TRACE",
            vec![
                ("content-length", "4"),
                ("authorization", "Basic dXNlcjpwYXNz"),
            ],
            Some(4),
        ));
        assert_eq!(all.len(), 2, "{all:?}");
        assert!(
            all[0].message.contains("MUST NOT send content"),
            "{}",
            all[0].message
        );
        assert!(
            all[1].message.contains("Authorization"),
            "{}",
            all[1].message
        );
    }

    /// The disclosure finding stays one however many fields it names: the
    /// sentence is about the request the client generated, and all three travel
    /// back in the same loop-back.
    #[test]
    fn every_disclosed_field_is_named_in_one_finding() {
        let all = check_all(&make_tx(
            "TRACE",
            vec![
                ("authorization", "Basic dXNlcjpwYXNz"),
                ("proxy-authorization", "Basic dXNlcjpwYXNz"),
                ("cookie", "session=8f1c2b"),
            ],
            Some(0),
        ));
        assert_eq!(all.len(), 1, "{all:?}");
        for named in ["Authorization", "Proxy-Authorization", "Cookie"] {
            assert!(all[0].message.contains(named), "{}", all[0].message);
        }
    }

    fn check(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        let rule = TraceMethodEcho;
        crate::test_helpers::run_rule(
            &rule,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    #[test]
    fn id_and_scope() {
        let r = TraceMethodEcho;
        assert_eq!(r.id(), "trace_method_echo");
        assert_eq!(r.scope(), crate::rules::RuleScope::Client);
    }

    #[rstest]
    // Nothing to reflect.
    #[case("TRACE", vec![], None, false)]
    #[case("TRACE", vec![("content-length", "0")], None, false)]
    #[case("TRACE", vec![], Some(0), false)]
    // Captured octets are the direct measurement.
    #[case("TRACE", vec![], Some(4), true)]
    // Declared, with no body captured to measure instead.
    #[case("TRACE", vec![("content-length", "4")], None, true)]
    // One value of five, written as a list on one line (RFC 9112 § 6.3).
    #[case("TRACE", vec![("content-length", "5, 5")], None, true)]
    // A Content-Length that does not parse leaves no number, and the rule that
    // owns the field reports the value.
    #[case("TRACE", vec![("content-length", "abc")], None, false)]
    // Framing is not content: the terminator chunk is all that streamed.
    #[case("TRACE", vec![("transfer-encoding", "chunked")], Some(0), false)]
    #[case("TRACE", vec![("transfer-encoding", "chunked")], Some(9), true)]
    // A framing field with nothing captured says nothing about content either.
    #[case("TRACE", vec![("transfer-encoding", "chunked")], None, false)]
    // The method token is case-sensitive.
    #[case("trace", vec![("content-length", "4")], Some(4), false)]
    #[case("Trace", vec![], Some(4), false)]
    // Another method carrying content is another rule's finding.
    #[case("POST", vec![("content-length", "4")], Some(4), false)]
    fn content_findings(
        #[case] method: &str,
        #[case] headers: Vec<(&str, &str)>,
        #[case] body_length: Option<u64>,
        #[case] expected: bool,
    ) {
        let v = check(&make_tx(method, headers, body_length));
        assert_eq!(v.is_some(), expected, "{v:?}");
        if let Some(v) = v {
            assert!(v.message.contains("MUST NOT send content"), "{v:?}");
        }
    }

    #[rstest]
    #[case(vec![("authorization", "Basic dXNlcjpwYXNz")], "Authorization")]
    #[case(vec![("proxy-authorization", "Basic dXNlcjpwYXNz")], "Proxy-Authorization")]
    #[case(vec![("cookie", "session=8f1c2b")], "Cookie")]
    fn sensitive_field_findings(#[case] headers: Vec<(&str, &str)>, #[case] named: &str) {
        let v = check(&make_tx("TRACE", headers, Some(0))).unwrap();
        assert!(v.message.contains(named), "{v:?}");
        assert!(v.message.contains("sensitive data"), "{v:?}");
    }

    /// A field carrying sensitive data under a name § 9.3.8 does not mention is
    /// outside what the rule can judge, and `description()` says so.
    #[test]
    fn an_unnamed_field_is_not_reported() {
        let v = check(&make_tx("TRACE", vec![("x-api-key", "s3cr3t")], Some(0)));
        assert!(v.is_none(), "{v:?}");
    }

    /// The sentence forbids a field *containing* sensitive data, so an empty
    /// one is not this rule's finding however unusual it is.
    #[rstest]
    #[case("")]
    #[case(" ")]
    #[case("\t ")]
    fn an_empty_named_field_is_not_reported(#[case] value: &str) {
        let v = check(&make_tx("TRACE", vec![("cookie", value)], Some(0)));
        assert!(v.is_none(), "{v:?}");
    }

    /// …and a value on any of the field's lines is still a value.
    #[test]
    fn a_second_field_line_carrying_a_value_is_reported() {
        let mut tx = make_tx("TRACE", vec![], Some(0));
        tx.request
            .headers
            .append("cookie", hyper::header::HeaderValue::from_static(""));
        tx.request.headers.append(
            "cookie",
            hyper::header::HeaderValue::from_static("session=8f1c2b"),
        );
        let v = check(&tx).unwrap();
        assert!(v.message.contains("Cookie"), "{v:?}");
    }

    #[test]
    fn every_sensitive_field_present_is_named_once() {
        let v = check(&make_tx(
            "TRACE",
            vec![
                ("authorization", "Basic dXNlcjpwYXNz"),
                ("proxy-authorization", "Basic dXNlcjpwYXNz"),
                ("cookie", "session=8f1c2b"),
            ],
            Some(0),
        ))
        .unwrap();
        assert!(
            v.message
                .contains("Authorization, Proxy-Authorization, Cookie"),
            "{v:?}"
        );
    }

    /// Content is reported first, because that sentence needs no example read
    /// into it to say what is wrong with the message.
    #[test]
    fn content_is_reported_before_the_fields() {
        let v = check(&make_tx(
            "TRACE",
            vec![("cookie", "session=8f1c2b"), ("content-length", "4")],
            None,
        ))
        .unwrap();
        assert!(v.message.contains("MUST NOT send content"), "{v:?}");
    }

    /// The media type of a TRACE response stopped being a requirement in
    /// RFC 9110, so a response says nothing here at all.
    #[rstest]
    #[case("text/plain")]
    #[case("message/http")]
    #[case("application/json")]
    fn response_media_type_is_not_judged(#[case] content_type: &str) {
        let mut tx = make_tx("TRACE", vec![], Some(0));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[
                ("content-type", content_type),
                ("content-length", "29"),
            ]),
            body_length: Some(29),
            trailers: None,
        });
        assert!(check(&tx).is_none());
    }

    /// A TRACE response with content and no `Content-Type` belongs to
    /// `content_type_present`, which reports it under RFC 9110 § 8.3 —
    /// asserted by running that rule, not by reading it.
    #[test]
    fn response_without_content_type_is_the_neighbours_finding() {
        let mut tx = make_tx("TRACE", vec![], Some(0));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("content-length", "29")]),
            body_length: Some(29),
            trailers: None,
        });
        assert!(check(&tx).is_none());

        let neighbour = crate::rules::REGISTERED_RULES
            .iter()
            .find(|r| r.id() == "content_type_present")
            .expect("the neighbour is registered");
        assert!(crate::test_helpers::run_rule(
            *neighbour,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[neighbour.id()]),
        )
        .is_some());
    }

    /// Every published snippet is run through the rule.
    #[test]
    fn published_examples_are_judged_by_this_rule() {
        use crate::rules::{Compliance, Rule as _};
        let rule = TraceMethodEcho;

        for ex in rule.examples() {
            let mut lines = ex.snippet.lines();
            let request_line = lines.next().expect("an example starts with a request line");
            assert!(
                request_line.starts_with("TRACE ") && request_line.ends_with(" HTTP/1.1"),
                "the first line of an example is its request line: {request_line:?}"
            );

            let mut pairs: Vec<(&str, &str)> = Vec::new();
            let mut body = String::new();
            let mut in_body = false;
            for line in lines {
                if line.is_empty() && !in_body {
                    in_body = true;
                    continue;
                }
                if in_body {
                    body.push_str(line);
                    continue;
                }
                let (name, value) = line.split_once(':').unwrap_or_else(|| {
                    panic!("example header line is not `Name: value`: {line:?}")
                });
                pairs.push((name, value.trim()));
            }

            let tx = make_tx(
                "TRACE",
                pairs,
                Some(u64::try_from(body.len()).expect("example bodies are small")),
            );
            let v = check(&tx);
            match ex.compliance {
                Compliance::Compliant => assert!(v.is_none(), "{}: {v:?}", ex.snippet),
                Compliance::NonCompliant => assert!(v.is_some(), "{}", ex.snippet),
            }
        }
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["trace_method_echo"]);
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
