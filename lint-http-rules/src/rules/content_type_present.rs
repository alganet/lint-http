// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::content_type::{CONTENT_TYPE_MISSING, RFC_9110_8_3};
use crate::violations::ViolationDef;

/// One entry: content with nothing saying how to read it.
static DECLARED: &[&ViolationDef] = &[&CONTENT_TYPE_MISSING];

pub struct ContentTypePresent;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9112_6_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9112",
    section: Some("6.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3",
    note: "Message body length — item 1 for the statuses and HEAD responses that carry no content, item 2 for CONNECT tunnels, item 8 for why a missing Content-Length is not evidence of a body",
};
const RFC_9110_15_3_6: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15.3.6"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.6",
    note: "205 Reset Content — bodiless by its own MUST NOT, and absent from §6.3's list",
};
const RFC_9110_9_3_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("9.3.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.2",
    note: "HEAD — no content is sent, so this rule's condition is never met; the same-header-fields SHOULD is another rule's subject",
};
const RFC_9110_6_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("6.4"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-6.4",
    note: "Content — the octets left once framing is taken off, which is what a request is measured by: a zero-length chunked body carries none",
};

impl RuleMeta for ContentTypePresent {
    fn id(&self) -> &'static str {
        "content_type_present"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Content-Type Present")
    }

    fn description(&self) -> &'static str {
        "Reports a message that carries content without a `Content-Type` describing it: a response, and a request.\n\n**This is a SHOULD, and it has a stated exception.** RFC 9110 §8.3: \"A sender that generates a message containing content SHOULD generate a Content-Type header field in that message *unless the intended media type of the enclosed representation is unknown to the sender*.\" Nothing on the wire separates a sender that did not know from one that did not bother, so both are reported — the finding is that the recipient was left to guess, not that a rule was broken.\n\n**Why the guess matters.** §8.3 gives a recipient two ways to proceed without the field: assume `application/octet-stream`, or examine the data. The second is content sniffing, and §8.3 spends a paragraph on it — it \"risks drawing incorrect conclusions about the data, which might expose the user to additional security risks (e.g., \\\"privilege escalation\\\")\".\n\n**Content, not headers.** The condition is that the message *contains content*, so the recorded body length decides it wherever one was captured. Only where nothing was captured does the rule fall back to header evidence, and then only to signals that assert content — a non-zero `Content-Length` or a `Transfer-Encoding`. A body whose reading stopped before its end takes that same fallback when it counted zero: the count is then a lower bound, which can assert content but cannot deny it. A 2xx that merely omits `Content-Length` is not evidence of a body; that is what an empty HTTP/2 response looks like.\n\n**Responses with nothing to describe are skipped**: `1xx`, `204`, `304` (RFC 9112 §6.3), `205` (RFC 9110 §15.3.6's MUST NOT), any response to `HEAD` (§9.3.2), and a `2xx` to `CONNECT`, whose trailing octets are a tunnel rather than content. Whether a HEAD response should still carry the `Content-Type` a `GET` would have sent is §9.3.2's same-header-fields SHOULD, which `head_response_headers_match_get` checks against the actual `GET`.\n\n**A request is a message too.** §8.3 says \"a sender\", and a client enclosing content in a `POST` or `PUT` leaves the server the same two guesses a server leaves a client. Content is §6.4's — the octets left once framing is taken off — so a request is measured the way the other request-content rules measure it: the captured octet count where there is one, the request's own `Content-Length` where nothing was captured, and a `Transfer-Encoding` alone asserts nothing, since a chunked body whose only chunk is the last one carries no content. A `GET`, `HEAD` or `DELETE` carrying content is reported here too, beside `method_content_forbidden`: §9.3.1 lets such content exist where the origin has agreed to it, and where it exists it is content like any other. Four methods are left to the rule that already reads the same request: `OPTIONS` (§9.3.7 makes the field a MUST, `options_method_capabilities`), `PATCH` (RFC 5789 §2 identifies a patch document by its media type, `patch_partial_update`), `TRACE` (§9.3.8 forbids the content itself, `trace_method_echo`), and `CONNECT`, whose request has no content and whose following octets are a tunnel (`request_version_method_valid`)."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_8_3,
            RFC_9112_6_3,
            RFC_9110_15_3_6,
            RFC_9110_9_3_2,
            RFC_9110_6_4,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::PerSite
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /page HTTP/1.1\n\nHTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8\nContent-Length: 3\n\nabc",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(no content, so nothing to describe)"),
                snippet: "GET /thing HTTP/1.1\n\nHTTP/1.1 204 No Content\n\n",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(a HEAD response sends no content)"),
                snippet: "HEAD /large.iso HTTP/1.1\n\nHTTP/1.1 200 OK\nContent-Length: 1048576\n\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the recipient is left to sniff)"),
                snippet: "GET /page HTTP/1.1\n\nHTTP/1.1 200 OK\nContent-Length: 3\n\nabc",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(a request whose content is labelled)"),
                snippet: "POST /items HTTP/1.1\nContent-Type: application/json\nContent-Length: 7\n\n{\"a\":1}\n\nHTTP/1.1 204 No Content\n\n",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(a request with no content has nothing to label)"),
                snippet: "POST /items/7/archive HTTP/1.1\nContent-Length: 0\n\nHTTP/1.1 204 No Content\n\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the server is left to sniff what the client sent)"),
                snippet: "POST /items HTTP/1.1\nContent-Length: 7\n\n{\"a\":1}\n\nHTTP/1.1 204 No Content\n\n",
            },
        ]
    }
}

impl Rule for ContentTypePresent {
    // No `needs_response`: a request is read whether or not anything answered
    // it, since what the client enclosed is on the wire either way.
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Two senders, two findings, and neither ends the reading of the
        // other: a client that sent untyped content and a server that answered
        // with untyped content are two repairs in two places.
        [request_untyped(tx, ctx), response_untyped(tx, ctx)]
            .into_iter()
            .flatten()
            .collect()
    }
}

/// The request half of § 8.3. The sentence says "a sender", and a request
/// that encloses content leaves the server the same two guesses a response
/// without the field leaves a client.
fn request_untyped(
    tx: &crate::http_transaction::HttpTransaction,
    ctx: &crate::rules::RuleContext<'_>,
) -> Option<Violation> {
    let method = tx.request.method.as_str();

    // Four methods already have a reader for exactly this request, and each
    // would say the same thing twice or ask for a label on octets another
    // finding says must not exist. Compared exactly: the method token is
    // case-sensitive, so `patch` is not PATCH and its content is still
    // unlabelled content.
    //
    // OPTIONS makes the field a MUST, reported by `options_method_capabilities`
    // as `method_options_content_type_missing`.
    // cite(RFC 9110 § 9.3.7): "A client that generates an OPTIONS request containing content MUST send a valid Content-Type header field describing the representation media type."
    // PATCH content is a patch document, which is identified by its media
    // type: `patch_partial_update`'s `method_patch_content_type_missing`.
    // cite(RFC 5789 § 2): "The set of changes is represented in a format called a "patch document" identified by a media type."
    // TRACE content is itself the defect, `trace_method_echo`'s
    // `method_trace_content_forbidden`; labelling it is not the repair.
    // cite(RFC 9110 § 9.3.8): "A client MUST NOT send content in a TRACE request."
    // A CONNECT request has none, and what follows it is the tunnel:
    // `request_version_method_valid`'s `method_connect_content_forbidden`.
    // cite(RFC 9110 § 9.3.6): "A CONNECT request message does not have content."
    if matches!(method, "OPTIONS" | "PATCH" | "TRACE" | "CONNECT") {
        return None;
    }

    // Content, not framing, measured by the helper every other request-content
    // rule uses: a chunked body whose only chunk is the last one carries none,
    // and over HTTP/2 and HTTP/3 content arrives with no framing field at all.
    // cite(RFC 9110 § 6.4): "HTTP messages often transfer a complete or partial representation as the message "content": a stream of octets sent after the header section, as delineated by the message framing."
    let evidence = crate::helpers::content_length::content_evidence(
        &tx.request.headers,
        tx.request.body_length,
        tx.request.body_interrupted,
    )?;

    // Presence is the whole test. A value that is empty or not a media type is
    // `content_type_valid`'s finding.
    if tx.request.headers.contains_key("content-type") {
        return None;
    }

    // A GET, HEAD or DELETE is not declined: § 9.3.1 and its siblings let such
    // content exist where the origin has agreed to it, and where it exists it
    // is content like any other. `method_content_forbidden` says it should not
    // be there; this says that, being there, it is unlabelled.
    // cite(RFC 9110 § 8.3): "A sender that generates a message containing content SHOULD generate a Content-Type header field in that message unless the intended media type of the enclosed representation is unknown to the sender."
    // cite(RFC 9110 § 8.3): "If a Content-Type header field is not present, the recipient MAY either assume a media type of "application/octet-stream" ([RFC2046], Section 4.5.1) or examine the data to determine its type."
    Some(ctx.by_client().report_with(
        &CONTENT_TYPE_MISSING,
        format!(
            "{method} request contains content ({evidence}) but no Content-Type header, \
             so the server is left to assume application/octet-stream or examine the data"
        ),
    ))
}

/// The response half, and the half this rule was written for.
fn response_untyped(
    tx: &crate::http_transaction::HttpTransaction,
    ctx: &crate::rules::RuleContext<'_>,
) -> Option<Violation> {
    let Some(resp) = &tx.response else {
        return None;
    };

    // The responses that carry no content, and so cannot be missing a
    // header field that describes content. The list had three entries and
    // needed six: a 205 declaring a Content-Length was reported for
    // omitting a Content-Type it has nothing to describe.
    //
    // A HEAD response is one of them, so § 8.3's condition -- "a message
    // containing content" -- is not met however large the resource is.
    // Whether it *should* still carry the Content-Type a GET would have
    // sent is a different sentence (§ 9.3.2's same-header-fields SHOULD)
    // and a different rule's finding: `head_response_headers_match_get`
    // compares the two transactions, and its configurable header list
    // already names `content-type`.
    //
    // A single-part 206 is not: its range is content, and the type it
    // names is the representation's.
    use crate::helpers::response_content::{response_content, ResponseContent};
    if response_content(&tx.request.method, resp.status, &resp.headers) == ResponseContent::Absent {
        return None;
    }

    if resp.headers.contains_key("content-type") {
        return None;
    }

    // The requirement is conditioned on the message *containing content*,
    // and the transaction records how many octets arrived. The rule
    // inferred it from header fields instead, and one of the three
    // inferences asserted a body from the *absence* of information: a 2xx
    // with no Content-Length was taken to have one. That is backwards --
    // § 6.3's last item says a response that declares no length is
    // delimited by the connection closing, which says nothing about
    // whether any octets arrive, and over HTTP/2 or HTTP/3 an ordinary
    // empty 200 carries no Content-Length at all. Every such response was
    // reported.
    // cite(RFC 9112 § 6.3): "Otherwise, this is a response message without a declared message body length, so the message body length is determined by the number of octets received prior to the server closing the connection."
    //
    // So the observation wins where there is one. `body_length` is `None`
    // only on the paths that never captured a body, and there the header
    // evidence is all there is -- but only the two signals that *assert*
    // content, never the absence of one.
    //
    // A count that stopped where the reading stopped is a lower bound, so
    // it can assert content and cannot deny it: above zero it settles the
    // question either way, and at zero it is no more informative than the
    // uncaptured case, which is where it goes.
    let has_content = match resp.body_length {
        Some(n) if n > 0 => true,
        Some(_) if !resp.body_interrupted => false,
        _ => {
            let declared = crate::helpers::content_length::validate_content_length(&resp.headers)
                .ok()
                .flatten();
            declared.is_some_and(|n| n > 0)
                || resp.headers.contains_key(hyper::header::TRANSFER_ENCODING)
        }
    };

    // The requirement, at last quoted. It is a **SHOULD**, and it carries
    // an exception the rule cannot evaluate: a sender that does not know
    // the media type is excused. Nothing on the wire distinguishes "did not
    // know" from "did not bother", so this reports both, and the
    // description says so rather than implying a MUST.
    // cite(RFC 9110 § 8.3): "A sender that generates a message containing content SHOULD generate a Content-Type header field in that message unless the intended media type of the enclosed representation is unknown to the sender."
    // cite(RFC 9110 § 8.3): "Content-Type = media-type"
    //
    // Omitting it is not a framing error, and § 8.3 gives the recipient two
    // ways to proceed -- which is exactly why this is worth reporting
    // rather than shrugging at. The second of those ways is content
    // sniffing, and § 8.3 spends a paragraph on what it costs:
    // cite(RFC 9110 § 8.3): "If a Content-Type header field is not present, the recipient MAY either assume a media type of "application/octet-stream" ([RFC2046], Section 4.5.1) or examine the data to determine its type."
    // cite(RFC 9110 § 8.3): "This "MIME sniffing" risks drawing incorrect conclusions about the data, which might expose the user to additional security risks (e.g., "privilege escalation")."
    if has_content {
        return Some(ctx.by_server().report_with(
            &CONTENT_TYPE_MISSING,
            "Response contains content but no Content-Type header".to_string(),
        ));
    }

    None
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ContentTypePresent;

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    #[rstest]
    #[case(200, vec![("content-type", "text/html")], false, None)]
    // No captured body on any of these, so the header evidence is all there
    // is. The bare 200 no longer counts as content: nothing asserts one.
    #[case(200, vec![], false, None)]
    #[case(204, vec![], false, None)]
    #[case(100, vec![], false, None)]
    #[case(101, vec![], false, None)]
    #[case(304, vec![], false, None)]
    #[case(200, vec![("content-length", "0")], false, None)]
    #[case(200, vec![("content-length", "10")], true, Some("Response contains content but no Content-Type header"))]
    #[case(404, vec![("content-type", "text/html")], false, None)]
    #[case(404, vec![("content-length", "10")], true, Some("Response contains content but no Content-Type header"))]
    #[case(500, vec![("transfer-encoding", "chunked")], true, Some("Response contains content but no Content-Type header"))]
    #[case(200, vec![("transfer-encoding", "chunked")], true, Some("Response contains content but no Content-Type header"))]
    fn check_response_cases(
        #[case] status: u16,
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
        #[case] expected_message: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = ContentTypePresent;

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(header_pairs.as_slice()),

            body_length: None,
            body_interrupted: false,
            trailers: None,
        });

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );

        if expect_violation {
            // The absence one sentence asks about outranks the one no sentence
            // asks about, which is the whole of this subject's ranking.
            let found = violation.clone().expect("a finding");
            assert_eq!(found.violation, "content_type_missing");
            assert_eq!(found.severity, crate::lint::Severity::Warn);
            assert_eq!(
                violation.map(|v| v.message),
                expected_message.map(|s| s.to_string())
            );
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    fn resp(
        status: u16,
        headers: &[(&str, &str)],
        body_length: Option<u64>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(headers),
            body_length,
            body_interrupted: false,
            trailers: None,
        });
        tx
    }

    /// A response whose reading stopped before the first octet arrived counted
    /// zero, and a zero that is only where the reading stopped cannot say the
    /// message carried no content. The sender's declaration answers instead, so
    /// the missing `Content-Type` is still reported.
    #[test]
    fn an_interrupted_zero_does_not_excuse_a_missing_content_type() {
        let mut tx = resp(200, &[("content-length", "4000")], Some(0));

        // Read to the end, zero octets is an empty body and there is no
        // representation whose type could be missing.
        assert!(run(&tx).is_none());

        tx.response.as_mut().expect("response").body_interrupted = true;
        let v = run(&tx).expect("the declaration says content was there to type");
        assert_eq!(v.violation, "content_type_missing");
    }

    fn run(tx: &crate::http_transaction::HttpTransaction) -> Option<crate::lint::Violation> {
        let rule = ContentTypePresent;
        crate::test_helpers::run_rule(
            &rule,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    /// Every published snippet is run through the rule. The old pair could not
    /// have been: one carried a `# Missing Content-Type` comment, which no HTTP
    /// message has, and neither showed a request — yet the request method
    /// decides two of the exemptions, and the request is now a message this
    /// rule reads, so its header fields and content are read too.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, RuleMeta as _};
        let rule = ContentTypePresent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        // A start line, header lines, then content after the blank line.
        fn message(part: &str) -> (&str, Vec<(&str, &str)>, &str) {
            let (head, body) = part.split_once("\n\n").unwrap_or((part, ""));
            let mut lines = head.lines();
            let start = lines.next().expect("a start line");
            let pairs = lines
                .map(|l| {
                    l.split_once(": ")
                        .unwrap_or_else(|| panic!("not a header line: {l:?}"))
                })
                .collect();
            (start, pairs, body)
        }

        for ex in rule.examples() {
            let at = ex
                .snippet
                .find("\nHTTP/1.1 ")
                .unwrap_or_else(|| panic!("no status line: {:?}", ex.snippet));
            let (req_part, resp_part) = (ex.snippet[..at].trim_end(), &ex.snippet[at + 1..]);
            let (req_line, req_pairs, req_body) = message(req_part);
            let (status_line, resp_pairs, resp_body) = message(resp_part);
            let method = req_line.split_whitespace().next().expect("no method");
            let status: u16 = status_line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| panic!("no status: {status_line:?}"));

            let mut tx = resp(status, &resp_pairs, Some(resp_body.len() as u64));
            tx.request.method = method.to_string();
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&req_pairs);
            tx.request.body_length = Some(req_body.len() as u64);

            let found = crate::test_helpers::run_rule(
                &rule,
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
                    assert!(
                        found.message.contains("no Content-Type header"),
                        "{found:?}"
                    );
                }
            }
        }
    }

    fn untyped_request(
        method: &str,
        headers: &[(&str, &str)],
        body_length: Option<u64>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = method.to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(headers);
        tx.request.body_length = body_length;
        tx
    }

    /// § 8.3 says "a sender", and a request enclosing content is one. Before
    /// this half existed a `POST` whose content nothing labelled drew nothing.
    #[rstest]
    #[case("POST", vec![("content-length", "5")], Some(5), "POST request contains content (5 octets captured)")]
    #[case("PUT", vec![("content-length", "5")], Some(5), "PUT request contains content (5 octets captured)")]
    // Nothing captured, so the sender's own length is the evidence.
    #[case("POST", vec![("content-length", "5")], None, "POST request contains content (Content-Length: 5)")]
    // A chunked body with data in it: the count settles it, not the framing.
    #[case("POST", vec![("transfer-encoding", "chunked")], Some(5), "(5 octets captured)")]
    // § 9.3.1 lets a GET carry content the origin agreed to; unlabelled, it is
    // still unlabelled, beside `method_content_forbidden`.
    #[case("GET", vec![("content-length", "5")], Some(5), "GET request contains content")]
    #[case("DELETE", vec![("content-length", "5")], Some(5), "DELETE request contains content")]
    // The method token is case-sensitive: `patch` is not PATCH, so no
    // PATCH-specific reader answers for it and this one does.
    #[case("patch", vec![("content-length", "5")], Some(5), "patch request contains content")]
    fn a_request_with_untyped_content_is_reported(
        #[case] method: &str,
        #[case] headers: Vec<(&str, &str)>,
        #[case] body_length: Option<u64>,
        #[case] fragment: &str,
    ) {
        let tx = untyped_request(method, &headers, body_length);
        let found = run(&tx).expect("untyped request content");
        assert_eq!(found.violation, "content_type_missing");
        assert_eq!(found.party, Some(crate::lint::Party::Client));
        assert!(found.message.contains(fragment), "{found:?}");
        assert!(
            found.message.contains("no Content-Type header"),
            "{found:?}"
        );
    }

    /// The other direction: no content, a label, or a method whose own rule
    /// already reads this request.
    #[rstest]
    #[case("POST", vec![("content-length", "0")], Some(0))]
    // A chunked body whose only chunk is the last one carries no content.
    #[case("POST", vec![("transfer-encoding", "chunked")], Some(0))]
    #[case("POST", vec![("content-type", "application/json"), ("content-length", "7")], Some(7))]
    #[case("GET", vec![], Some(0))]
    #[case("OPTIONS", vec![("content-length", "5")], Some(5))]
    #[case("PATCH", vec![("content-length", "5")], Some(5))]
    #[case("TRACE", vec![("content-length", "5")], Some(5))]
    #[case("CONNECT", vec![("content-length", "5")], None)]
    fn a_request_with_nothing_untyped_is_not_reported(
        #[case] method: &str,
        #[case] headers: Vec<(&str, &str)>,
        #[case] body_length: Option<u64>,
    ) {
        let tx = untyped_request(method, &headers, body_length);
        assert!(run(&tx).is_none(), "{method} {headers:?} {body_length:?}");
    }

    /// Each half names its own sender, and a finding about one does not end
    /// the reading of the other. A request nothing answered is still read.
    #[test]
    fn both_halves_are_read_and_each_names_its_sender() {
        let mut tx = untyped_request("POST", &[("content-length", "5")], Some(5));
        tx.response = resp(200, &[("content-length", "3")], Some(3)).response;
        let all = crate::test_helpers::run_rule_all(
            &ContentTypePresent,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["content_type_present"]),
        );
        let parties: Vec<_> = all.iter().map(|v| v.party).collect();
        assert_eq!(
            parties,
            vec![
                Some(crate::lint::Party::Client),
                Some(crate::lint::Party::Server)
            ],
            "{all:?}"
        );
        assert_eq!(
            all[1].message,
            "Response contains content but no Content-Type header"
        );

        tx.response = None;
        let v = run(&tx).expect("the request is read with no response");
        assert_eq!(v.party, Some(crate::lint::Party::Client));
    }

    /// Responses that carry no content cannot be missing a field that describes
    /// content. The skip list had 1xx, 204 and 304; these three were reported.
    #[rstest]
    #[case("HEAD", 200, vec![("content-length", "1048576")])]
    #[case("HEAD", 200, vec![("transfer-encoding", "chunked")])]
    #[case("GET", 205, vec![("content-length", "10")])]
    #[case("CONNECT", 200, vec![("content-length", "10")])]
    #[case("CONNECT", 299, vec![("transfer-encoding", "chunked")])]
    fn a_response_with_no_content_is_not_missing_a_content_type(
        #[case] method: &str,
        #[case] status: u16,
        #[case] headers: Vec<(&str, &str)>,
    ) {
        let mut tx = resp(status, &headers, None);
        tx.request.method = method.to_string();
        assert!(
            run(&tx).is_none(),
            "{method} -> {status} carries no content to describe"
        );
    }

    /// The exemptions are bounded: a CONNECT that did not tunnel, and every
    /// ordinary method, are still checked.
    #[rstest]
    #[case("GET", 200)]
    #[case("CONNECT", 405)]
    #[case("POST", 201)]
    // The method token is case-sensitive, so neither of the two exempt methods
    // is exempt in another case: `Head` names no method and the response to it
    // carries content like any other.
    #[case("Head", 200)]
    #[case("head", 200)]
    #[case("Connect", 200)]
    #[case("connect", 299)]
    fn ordinary_responses_are_still_checked(#[case] method: &str, #[case] status: u16) {
        let mut tx = resp(status, &[("content-length", "10")], None);
        tx.request.method = method.to_string();
        assert!(run(&tx).is_some());
    }

    /// Where the octets were counted, the count decides. The rule used to infer
    /// a body from header fields even when it had the answer.
    #[rstest]
    #[case(Some(0), false)]
    #[case(Some(7), true)]
    fn the_observed_body_decides(#[case] body_length: Option<u64>, #[case] expect: bool) {
        assert_eq!(run(&resp(200, &[], body_length)).is_some(), expect);
    }

    /// A 2xx without Content-Length was taken to have a body, which asserts
    /// content from the absence of information -- and is what an ordinary empty
    /// HTTP/2 response looks like.
    #[rstest]
    #[case(200)]
    #[case(201)]
    #[case(299)]
    fn a_2xx_without_framing_headers_is_not_evidence_of_content(#[case] status: u16) {
        assert!(
            run(&resp(status, &[], Some(0))).is_none(),
            "an empty {status} declares no length and carries nothing"
        );
    }

    /// With no observation, the two positive signals still stand.
    #[rstest]
    #[case(vec![("content-length", "10")], true)]
    #[case(vec![("transfer-encoding", "chunked")], true)]
    #[case(vec![("content-length", "0")], false)]
    #[case(vec![], false)]
    fn without_an_observation_only_positive_evidence_counts(
        #[case] headers: Vec<(&str, &str)>,
        #[case] expect: bool,
    ) {
        assert_eq!(run(&resp(200, &headers, None)).is_some(), expect);
    }

    /// The Content-Length read goes through the shared validator, so a
    /// malformed one is nobody's evidence and § 6.3's comma list is one value.
    #[rstest]
    #[case("abc", false)]
    #[case("10, 10", true)]
    #[case("0, 0", false)]
    fn the_declared_length_is_read_by_the_shared_validator(#[case] cl: &str, #[case] expect: bool) {
        assert_eq!(
            run(&resp(200, &[("content-length", cl)], None)).is_some(),
            expect
        );
    }

    #[test]
    fn check_missing_response() {
        let rule = ContentTypePresent;
        let tx = crate::test_helpers::make_test_transaction();
        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(violation.is_none());
    }
}
