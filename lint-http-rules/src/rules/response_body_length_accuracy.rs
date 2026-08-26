// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ResponseBodyLengthAccuracy;

impl Rule for ResponseBodyLengthAccuracy {
    fn id(&self) -> &'static str {
        "response_body_length_accuracy"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let resp = tx.response.as_ref()?;

        // The whole `Content-Length` grammar used to be transcribed here --
        // `1*DIGIT`, the u128 ceiling, the multiple-values-differ check, the
        // non-UTF8 branch -- with message strings byte-identical to
        // `content_length_valid`'s, which owns the field's syntax on both
        // sides. Two identical findings for one defect, and a copy that had
        // stopped receiving the owner's fixes: it rejected `Content-Length:
        // 3, 3`, which § 6.3 makes valid. The request-side twin of this rule
        // carried the same two problems.
        //
        // Nothing is re-quoted. A syntax error leaves no number to compare, so
        // this rule declines and the syntax rule reports.
        // cite(RFC 9112 § 6.3): "The length of a message body is determined by one of the following (in order of precedence)"
        let declared = crate::helpers::headers::validate_content_length(&resp.headers).ok()??;

        // § 6.3's list is in precedence order, and the first two items are
        // about responses that cannot carry a body at all. This rule started at
        // item 6 and never read up.
        //
        // Item 1: a response to HEAD, and any 1xx, 204 or 304, ends at the
        // blank line -- "regardless of the header fields present". So the
        // captured length is zero by construction, and comparing a declared
        // length against it measures nothing.
        // cite(RFC 9112 § 6.3): "Any response to a HEAD request and any response with a 1xx (Informational), 204 (No Content), or 304 (Not Modified) status code is always terminated by the first empty line after the header fields, regardless of the header fields present in the message, and thus cannot contain a message body or trailer section."
        //
        // The Content-Length is not wrong in such a response -- it is
        // *deliberately* the length of a body that was not sent, and RFC 9110
        // makes that its defined meaning, twice, in a MUST:
        // cite(RFC 9110 § 8.6): "A server MAY send a Content-Length header field in a response to a HEAD request (Section 9.3.2); a server MUST NOT send Content-Length in such a response unless its field value equals the decimal number of octets that would have been sent in the content of a response if the same request had used the GET method."
        // cite(RFC 9110 § 8.6): "A server MAY send a Content-Length header field in a 304 (Not Modified) response to a conditional GET request (Section 15.4.5); a server MUST NOT send Content-Length in such a response unless its field value equals the decimal number of octets that would have been sent in the content of a 200 (OK) response to the same request."
        //
        // So the rule was reporting
        //
        //     HEAD /large.iso
        //     HTTP/1.1 200 OK
        //     Content-Length: 1048576
        //
        // -- a response conforming to a MUST -- for every HEAD of a non-empty
        // resource. § 9.3.2 asks servers to answer HEAD with the same fields
        // they would send for GET, so this is the common case, not a corner.
        // cite(RFC 9110 § 9.3.2): "The server SHOULD send the same header fields in response to a HEAD request as it would have sent if the request method had been GET."
        //
        // Whether the declared length matches what a GET *would* have returned
        // is the real requirement, and nothing in one transaction can answer
        // it: the octets it describes were never sent. `head_response_headers_match_get`
        // is the rule with two transactions to compare.
        let head_request = tx.request.method.eq_ignore_ascii_case("HEAD");
        let bodiless_status =
            (100..200).contains(&resp.status) || resp.status == 204 || resp.status == 304;
        if head_request || bodiless_status {
            // Item 1 does still say something checkable about these, and
            // exempting them from the comparison would have thrown it away: not
            // that the declared length is wrong, but that there must be *no
            // body at all*.
            //
            // Item 1 names two things, though, and only one of them is this
            // rule's to report now. `no_body_for_1xx_204_304` reads the
            // captured octets for the three statuses, and reads them without
            // needing a `Content-Length` first -- which this rule does need, its
            // whole entry point being a declared length. So the statuses are
            // left to it, and what stays here is the half its status gate cannot
            // reach: a response to HEAD that carries octets whatever its status.
            // Keeping both would have been two findings for one defect.
            if !bodiless_status && resp.body_length.is_some_and(|n| n > 0) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "A {} response to {} cannot contain a message body, but {} body \
                         octets were received",
                        resp.status,
                        tx.request.method,
                        resp.body_length.unwrap_or(0)
                    ),
                });
            }
            return None;
        }

        // Item 2: a 2xx to CONNECT turns the connection into a tunnel, and what
        // follows the header section is tunnelled octets rather than content.
        // The field is to be ignored outright.
        // cite(RFC 9112 § 6.3): "Any 2xx (Successful) response to a CONNECT request implies that the connection will become a tunnel immediately after the empty line that concludes the header fields."
        // cite(RFC 9112 § 6.3): "A client MUST ignore any Content-Length or Transfer-Encoding header fields received in such a message."
        if tx.request.method.eq_ignore_ascii_case("CONNECT") && (200..300).contains(&resp.status) {
            return None;
        }

        // Item 3, and then item 6 -- the sentence that licenses the comparison
        // at all, whose condition is "without Transfer-Encoding". With one
        // present the declared length is a number the specification says to
        // disregard, and the body length comes from decoding the transfer
        // coding instead, which is what the captured count already reflects.
        // cite(RFC 9112 § 6.3): "If a message is received with both a Transfer-Encoding and a Content-Length header field, the Transfer-Encoding overrides the Content-Length."
        // cite(RFC 9112 § 6.3): "If a valid Content-Length header field is present without Transfer-Encoding, its decimal value defines the expected message body length in octets."
        //
        // Carrying both is its own MUST NOT and its own rule's finding;
        // presence is what overrides, not validity.
        // cite(RFC 9112 § 6.2): "A sender MUST NOT send a Content-Length header field in any message that contains a Transfer-Encoding header field."
        if resp.headers.contains_key(hyper::header::TRANSFER_ENCODING) {
            return None;
        }

        // What is left is item 6's case, and § 8.6 says why a difference in it
        // is worth reporting rather than merely noting: this proxy is an
        // intermediary, and forwarding such a message is how a length
        // disagreement becomes a response-splitting bug downstream.
        // cite(RFC 9110 § 8.6): "As a result, a sender MUST NOT forward a message with a Content-Length header field value that is known to be incorrect."
        // cite(RFC 9112 § 6.2): "For messages that do include content, the Content-Length field value provides the framing information necessary for determining where the data (and message) ends."
        //
        // A response with neither field is close-delimited and declares no
        // length, so there is nothing to check and the early return above has
        // already happened.
        // cite(RFC 9112 § 6.3): "Otherwise, this is a response message without a declared message body length, so the message body length is determined by the number of octets received prior to the server closing the connection."
        //
        // `body_length` counts the octets that streamed through with the
        // transfer coding resolved and any `Content-Encoding` left encoded,
        // which is what `Content-Length` counts too.
        // cite(RFC 9110 § 8.6): "The "Content-Length" header field indicates the associated representation's data length as a decimal non-negative integer number of octets."
        if let Some(body_len) = resp.body_length {
            if declared != body_len as u128 {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "Content-Length ({}) does not match captured body bytes ({})",
                        declared, body_len
                    ),
                });
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "Checks that a response's `Content-Length` matches the number of body octets actually observed. RFC 9112 §6.2 makes that value the framing — \"necessary for determining where the data (and message) ends\" — and RFC 9110 §8.6 says why a proxy in particular must care: \"a sender MUST NOT forward a message with a Content-Length header field value that is known to be incorrect\". A length that disagrees with the framing is how response splitting reaches the next hop.\n\n**RFC 9112 §6.3 lists eight ways a body length is determined, in precedence order, and this rule is item 6.** The items above it are the reason most of what follows is an exemption rather than a check:\n\n- *Item 1* — a response to `HEAD`, and any `1xx`, `204` or `304`, ends at the blank line \"regardless of the header fields present\". Its `Content-Length` describes a body that was deliberately not sent: §8.6 requires, in a MUST, that a HEAD response's value equal what a `GET` would have returned, and a 304's equal what a `200` would have. Comparing either against zero captured octets reports a conforming response, so these are not measured here. Whether the value matches what a GET *would* have returned needs two transactions; `head_response_headers_match_get` has them. What item 1 *does* say about these is checkable and is checked: there must be no body at all, so a `204` that answered with content is reported for the body's existence rather than for any mismatch. Nothing else looks — the rule covering these statuses reads the header fields that advertise a body, not the body.\n- *Item 2* — a `2xx` to `CONNECT` becomes a tunnel, and a client \"MUST ignore any Content-Length or Transfer-Encoding header fields received in such a message\".\n- *Item 3* — when `Transfer-Encoding` is also present it overrides, so the declared length is disregarded. Carrying both is its own MUST NOT (§6.2) and `content_length_vs_transfer_encoding` reports it.\n- *Item 8* — a response with no declared length is close-delimited; there is nothing to compare.\n\n**Syntax belongs to another rule.** A value that is not `1*DIGIT`, or whose field lines disagree, leaves no number to compare, so this rule declines and `content_length_valid` reports it. That rule also implements §6.3's allowance for `Content-Length: 42, 42` — a comma list of equal values is one value, not a malformed field.\n\n**What the comparison is against.** The recorded length counts octets that streamed through with the transfer coding resolved and any `Content-Encoding` left encoded — which is what `Content-Length` counts. Where no body was captured, nothing is claimed."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("6.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3",
                note: "Message body length, in precedence order — this rule is item 6, and items 1, 2 and 3 are why most responses are exempt rather than checked",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.6"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6",
                note: "Content-Length: the field, its grammar, the MUSTs that make a HEAD or 304 response's value describe a body it did not send, and the MUST NOT against forwarding a value known to be incorrect — this rule's reason to exist",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("6.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6.2",
                note: "Content-Length as framing, and the MUST NOT against sending it beside Transfer-Encoding — another rule's finding",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("9.3.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.2",
                note: "HEAD — servers SHOULD answer it with the fields they would have sent for GET, which is what made the exemption the common case rather than a corner",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /x HTTP/1.1\n\nHTTP/1.1 200 OK\nContent-Length: 3\n\nabc",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(a HEAD response declares what a GET would have returned)"),
                snippet: "HEAD /large.iso HTTP/1.1\n\nHTTP/1.1 200 OK\nContent-Length: 1048576\n\n",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(304 declares what a 200 would have returned)"),
                snippet: "GET /x HTTP/1.1\n\nHTTP/1.1 304 Not Modified\nContent-Length: 1024\n\n",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(Transfer-Encoding overrides, so nothing here is measured)"),
                snippet: "GET /x HTTP/1.1\n\nHTTP/1.1 200 OK\nContent-Length: 10\nTransfer-Encoding: chunked\n\nabc",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the response is incomplete, and must not be forwarded)"),
                snippet: "GET /x HTTP/1.1\n\nHTTP/1.1 200 OK\nContent-Length: 10\n\nabc",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ResponseBodyLengthAccuracy;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn matching_content_length_and_body_no_violation() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("content-length", "3")]),
            body_length: Some(3),
            trailers: None,
        });

        let rule = ResponseBodyLengthAccuracy;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn mismatching_content_length_and_body_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("content-length", "10")]),
            body_length: Some(3),
            trailers: None,
        });

        let rule = ResponseBodyLengthAccuracy;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Content-Length"));
    }

    #[test]
    fn no_content_length_present_no_violation() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[]),
            body_length: Some(5),
            trailers: None,
        });

        let rule = ResponseBodyLengthAccuracy;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn content_length_present_but_no_captured_body_no_violation() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("content-length", "3")]),
            body_length: None,
            trailers: None,
        });

        let rule = ResponseBodyLengthAccuracy;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn response_304_with_matching_content_length_no_violation() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(304, &[]);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 304,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("content-length", "0")]),
            body_length: Some(0),
            trailers: None,
        });

        let rule = ResponseBodyLengthAccuracy;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn multiple_identical_content_length_headers_no_violation() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        use hyper::header::HeaderValue;
        hm.append("content-length", HeaderValue::from_static("3"));
        hm.append("content-length", HeaderValue::from_static("3"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,
            body_length: Some(3),
            trailers: None,
        });

        let rule = ResponseBodyLengthAccuracy;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(
            v.is_none(),
            "identical multiple Content-Length headers should not be a violation"
        );
    }

    fn resp_with(
        status: u16,
        headers: &[(&str, &str)],
        body_length: Option<u64>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(headers),
            body_length,
            trailers: None,
        });
        tx
    }

    fn run(tx: &crate::http_transaction::HttpTransaction) -> Option<crate::lint::Violation> {
        let rule = ResponseBodyLengthAccuracy;
        rule.check_transaction(
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    /// Every published snippet is run through the rule. These now carry the
    /// request line as well, because three of the five exemptions depend on the
    /// request method and the old snippets showed only the response -- a HEAD
    /// example that does not say it is a HEAD cannot illustrate anything.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, Rule as _};
        let rule = ResponseBodyLengthAccuracy;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        for ex in rule.examples() {
            // request-line \n\n status-line \n headers \n\n body
            let (req_part, resp_part) = ex
                .snippet
                .split_once("\n\n")
                .unwrap_or_else(|| panic!("no request/response split: {:?}", ex.snippet));
            let method = req_part
                .split_whitespace()
                .next()
                .unwrap_or_else(|| panic!("no method: {req_part:?}"));
            let (head, body) = resp_part
                .split_once("\n\n")
                .unwrap_or_else(|| panic!("no header/body split: {resp_part:?}"));
            let mut lines = head.lines();
            let status_line = lines.next().expect("no status line");
            let status: u16 = status_line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| panic!("no status: {status_line:?}"));
            let pairs: Vec<(&str, &str)> = lines
                .map(|l| {
                    l.split_once(": ")
                        .unwrap_or_else(|| panic!("not a header line: {l:?}"))
                })
                .collect();

            let mut tx = resp_with(status, &pairs, Some(body.len() as u64));
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
                    assert!(
                        found.message.contains("does not match captured body bytes"),
                        "{found:?}"
                    );
                }
            }
        }
    }

    /// § 6.3 item 6 licenses this comparison only "without Transfer-Encoding";
    /// item 3 says the Transfer-Encoding overrides. Presence is what overrides,
    /// not validity.
    #[rstest]
    #[case("chunked")]
    #[case("gzip, chunked")]
    #[case("nonsense")]
    #[case("")]
    fn transfer_encoding_overrides_and_leaves_nothing_to_measure(#[case] te: &str) {
        let tx = resp_with(
            200,
            &[("content-length", "10"), ("transfer-encoding", te)],
            Some(3),
        );
        assert!(run(&tx).is_none(), "Transfer-Encoding: {te:?} overrides");
    }

    /// § 6.3 item 1: these responses end at the blank line "regardless of the
    /// header fields present", so the captured length is zero by construction.
    /// The declared length is not wrong -- RFC 9110 § 8.6 makes it, in a MUST,
    /// the size of the body a GET would have returned. Every HEAD of a
    /// non-empty resource was reported.
    #[rstest]
    #[case("HEAD", 200, "1048576")]
    #[case("HEAD", 200, "3")]
    #[case("GET", 304, "1024")]
    #[case("GET", 204, "1024")]
    #[case("GET", 100, "1024")]
    #[case("GET", 199, "1024")]
    fn a_response_that_cannot_carry_a_body_is_not_measured(
        #[case] method: &str,
        #[case] status: u16,
        #[case] cl: &str,
    ) {
        let mut tx = resp_with(status, &[("content-length", cl)], Some(0));
        tx.request.method = method.to_string();
        assert!(
            run(&tx).is_none(),
            "{method} -> {status} with Content-Length: {cl} declares a body it did not send"
        );
    }

    /// Item 1 still says something checkable about a HEAD response: not that the
    /// declared length is wrong, but that there must be no body at all. This is
    /// the half of item 1 the sibling's status gate cannot reach.
    #[rstest]
    #[case(200)]
    #[case(404)]
    fn a_head_response_that_sent_octets_is_reported(#[case] status: u16) {
        let mut tx = resp_with(status, &[("content-length", "1024")], Some(7));
        tx.request.method = "HEAD".into();
        assert!(
            run(&tx).is_some_and(|v| v.message.contains("cannot contain a message body")),
            "HEAD -> {status} sent 7 octets"
        );
    }

    /// The finding is the body's existence, not its size: a response whose
    /// captured octets happen to equal its declared length still has a body, and
    /// the message says so rather than reporting a match.
    #[test]
    fn the_finding_is_the_body_not_the_mismatch() {
        let mut tx = resp_with(200, &[("content-length", "7")], Some(7));
        tx.request.method = "HEAD".into();
        let v = run(&tx).expect("a HEAD response with 7 body octets has a body");
        assert!(v.message.contains("cannot contain a message body"), "{v:?}");
        assert!(!v.message.contains("does not match"), "{v:?}");
    }

    /// The three statuses moved to the rule named for them, and the handover is
    /// checked by running it rather than by reading it: this rule declines, and
    /// the sibling reports -- including the case that has no `Content-Length` for
    /// this rule's entry point to have found in the first place.
    #[rstest]
    #[case(204, &[("content-length", "1024")][..])]
    #[case(304, &[("content-length", "1024")][..])]
    #[case(100, &[("content-length", "1024")][..])]
    #[case(204, &[][..])]
    #[case(304, &[("transfer-encoding", "chunked")][..])]
    fn the_three_statuses_are_reported_by_the_sibling_and_not_here(
        #[case] status: u16,
        #[case] headers: &[(&str, &str)],
    ) {
        let mut tx = resp_with(status, headers, Some(7));
        tx.request.method = "GET".into();
        assert!(run(&tx).is_none(), "{status} is not this rule's to report");

        let sibling = crate::rules::REGISTERED_RULES
            .iter()
            .find(|r| r.id() == "no_body_for_1xx_204_304")
            .expect("the sibling rule is registered");
        let found = sibling.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[sibling.id()]),
        );
        assert!(
            found.is_some_and(|v| v.message.contains("content octets")),
            "{status} sent 7 octets and nothing reported it"
        );
    }

    /// § 6.3 item 2: the octets after a tunnelling 2xx are not content, and the
    /// field is to be ignored outright.
    #[rstest]
    #[case(200)]
    #[case(299)]
    fn a_tunnelling_connect_response_is_not_measured(#[case] status: u16) {
        let mut tx = resp_with(status, &[("content-length", "10")], Some(0));
        tx.request.method = "CONNECT".into();
        assert!(run(&tx).is_none());
    }

    /// The exemptions are bounded: an ordinary GET still gets measured, and a
    /// CONNECT that did not tunnel is an ordinary response.
    #[rstest]
    #[case("GET", 200)]
    #[case("CONNECT", 405)]
    #[case("GET", 404)]
    fn ordinary_responses_are_still_measured(#[case] method: &str, #[case] status: u16) {
        let mut tx = resp_with(status, &[("content-length", "10")], Some(3));
        tx.request.method = method.to_string();
        assert!(run(&tx).is_some_and(|v| v.message.contains("does not match")));
    }

    /// A malformed value leaves no number to compare, so this rule declines and
    /// `content_length_valid` -- which owns the field's syntax and reports
    /// these with the same message strings -- makes the report. Six tests here
    /// used to assert the duplicates.
    #[rstest]
    #[case("abc")]
    #[case("+1")]
    #[case("")]
    #[case("340282366920938463463374607431768211456")]
    fn a_malformed_value_is_left_to_the_rule_that_owns_the_syntax(#[case] cl: &str) {
        assert!(run(&resp_with(200, &[("content-length", cl)], Some(3))).is_none());
    }

    #[test]
    fn values_that_disagree_are_left_to_the_syntax_rule() {
        use hyper::header::HeaderValue;
        let mut tx = resp_with(200, &[], Some(10));
        let mut hm = hyper::HeaderMap::new();
        hm.append("content-length", HeaderValue::from_static("10"));
        hm.append("content-length", HeaderValue::from_static("20"));
        tx.response.as_mut().unwrap().headers = hm;
        assert!(run(&tx).is_none());
    }

    /// § 6.3 makes a comma-separated list of equal values one value, and RFC
    /// 9110 § 8.6 names `Content-Length: 42, 42` as the case it is thinking of.
    /// The inline copy of the grammar rejected it.
    #[rstest]
    #[case("3, 3", Some(3), false)]
    #[case("3, 3", Some(4), true)]
    fn a_comma_list_of_equal_values_is_one_value(
        #[case] cl: &str,
        #[case] body: Option<u64>,
        #[case] expect: bool,
    ) {
        assert_eq!(
            run(&resp_with(200, &[("content-length", cl)], body)).is_some(),
            expect
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "response_body_length_accuracy");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn validate_rules_with_invalid_config_missing_severity() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "response_body_length_accuracy");
        // remove severity to simulate invalid config
        if let Some(toml::Value::Table(ref mut table)) =
            cfg.rules.get_mut("response_body_length_accuracy")
        {
            table.remove("severity");
        }

        let err = crate::rules::validate_rules(&cfg).expect_err("expected validation to fail");
        assert!(err.to_string().contains("Missing required 'severity'"));
    }
}
