// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct NoBodyFor1xx204304;

impl NoBodyFor1xx204304 {
    /// The one place a finding is built. Every call site says the same thing about
    /// the message -- this status cannot carry what it is carrying -- and differs
    /// only in `detail`, which names the evidence and the sentence behind it. That
    /// clause is what a test keys on, because the rest of the message is a rule
    /// invariant and asserting it asserts nothing.
    fn report(&self, severity: crate::lint::Severity, status: u16, detail: &str) -> Violation {
        self.violation(severity, format!("A {status} response {detail}"))
    }
}

impl Rule for NoBodyFor1xx204304 {
    fn id(&self) -> &'static str {
        "no_body_for_1xx_204_304"
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
            let resp = tx.response.as_ref()?;
            let status = resp.status;

            // The status set, and the sentence each member gets. § 6.4.1's summary is
            // where the rule's name came from, and it is a statement about *content*:
            // it says these responses have none, and says nothing about which header
            // fields they may carry. Reading it as a rule about fields is what put a
            // 304 in front of two prohibitions that exempt it by name, below.
            // cite(RFC 9110 § 6.4.1): "All 1xx (Informational), 204 (No Content), and 304 (Not Modified) responses do not include content."
            //
            // The requirement itself is written once per status, in three identical
            // sentences, and each names one thing § 6.4.1's summary leaves out:
            // trailers.
            // cite(RFC 9110 § 15.2): "A 1xx response is terminated by the end of the header section; it cannot contain content or trailers."
            // cite(RFC 9110 § 15.3.5): "A 204 response is terminated by the end of the header section; it cannot contain content or trailers."
            // cite(RFC 9110 § 15.4.5): "A 304 response is terminated by the end of the header section; it cannot contain content or trailers."
            //
            // And once more as framing, where "regardless of the header fields present"
            // is the reason the two checks that read a *field* are separate from the two
            // that read what arrived: a field cannot make one of these responses carry a
            // body, so a field's presence is a defect of its own and not evidence.
            // cite(RFC 9112 § 6.3): "Any response to a HEAD request and any response with a 1xx (Informational), 204 (No Content), or 304 (Not Modified) status code is always terminated by the first empty line after the header fields, regardless of the header fields present in the message, and thus cannot contain a message body or trailer section."
            //
            // 205 is deliberately not in this set, and the difference is not an
            // oversight: its prohibition is on *generating content*, its framing is
            // ordinary, and so a `Content-Length: 0` on a 205 is conforming where the
            // same field on a 204 is a MUST NOT violation. Same words, different
            // evidence; it needs its own rule rather than a fourth arm here.
            // cite(RFC 9110 § 15.3.6): "Since the 205 status code implies that no additional content will be provided, a server MUST NOT generate content in a 205 response."
            let is_1xx = (100..200).contains(&status);
            let is_204 = status == 204;
            if !(is_1xx || is_204 || status == 304) {
                return None;
            }

            // What arrived, before what was advertised. The captured count is of
            // *content* -- chunk sizes and the trailer section are not in it -- so any
            // count above zero is the violation itself rather than a claim about one.
            // cite(RFC 9110 § 6.4): "This abstract definition of content reflects the data after it has been extracted from the message framing."
            //
            // Two rules read `body_length` for these statuses before this one did, and
            // both were run rather than read. `response_body_length_accuracy`
            // reaches its check only behind `validate_content_length(...).ok()??`, so a
            // 204 answering with a chunked body and no declared length -- precisely the
            // case chunked framing produces -- was invisible to it; it has handed the
            // three statuses over. `http3_status_code_valid` had all three of
            // the checks below, for 1xx only, behind a gate requiring both the request
            // and the response to be HTTP/3, which left the same defect over HTTP/1.1
            // unreported and would now double-report the HTTP/3 one; the sentence it
            // enforced is § 15.2's and says nothing about HTTP/3, so it kept § 4.5's
            // 101 and surrendered these.
            if let Some(n) = resp.body_length {
                if n > 0 {
                    return Some(self.report(
                        ctx.severity,
                        status,
                        &format!(
                            "is terminated by the end of its header section and cannot contain \
                             content, but {n} content octets were received"
                        ),
                    ));
                }
            }

            // The three sentences above say "content or trailers", and § 6.3 says
            // "message body or trailer section". A trailer section exists only inside a
            // message body's framing, so its presence is a violation whether or not it
            // carries any fields -- what is forbidden is the section, not its members.
            // `None` here means no trailer section was observed; `Some` means one was,
            // in both producers (the proxy fills it from the frame that carried it, and
            // the `lint` subcommand deserializes it from a capture file).
            //
            // `trailer_fields_valid` judges *which* fields a trailer section
            // may hold. Whether the response was allowed a trailer section at all is
            // this rule's question. `http3_status_code_valid` asked it for
            // HTTP/3 1xx responses, empty section included, and reached the same
            // answer -- that `#[test]` is the reason the empty case is pinned here.
            if resp.trailers.is_some() {
                return Some(self.report(
                    ctx.severity,
                    status,
                    "is terminated by the end of its header section and cannot contain trailers, \
                     but a trailer section was received",
                ));
            }

            // A `Content-Length` on a 1xx or a 204 is forbidden at *any* value. The
            // rule used to require a value above zero, so `204` + `Content-Length: 0` --
            // the form a server writes precisely because it believes it is being
            // explicit about emptiness -- violated a MUST NOT that nothing reported, and
            // a `#[case]` asserted the silence.
            // cite(RFC 9110 § 8.6): "A server MUST NOT send a Content-Length header field in any response with a status code of 1xx (Informational) or 204 (No Content)."
            //
            // Because presence is the whole test, no value is parsed here. The rule used
            // to run its own reader over one field line -- `to_str().ok().and_then(|s|
            // s.trim().parse::<usize>().ok())` -- which took only the first line,
            // accepted `+5`, dropped a non-UTF-8 value in silence, and rejected the
            // `5, 5` form § 6.3 makes valid. All of it was answering a question the
            // sentence does not ask. `content_length_valid` owns the field's syntax.
            //
            // The 304 is not here. § 8.6 permits the field on one by name, and gives it
            // a defined meaning -- the length of the 200 that was not sent:
            // cite(RFC 9110 § 8.6): "A server MAY send a Content-Length header field in a 304 (Not Modified) response to a conditional GET request (Section 15.4.5); a server MUST NOT send Content-Length in such a response unless its field value equals the decimal number of octets that would have been sent in the content of a 200 (OK) response to the same request."
            //
            // That MAY's own MUST NOT is undecidable from one exchange: the octets it
            // compares against were never sent, so no capture holds them. It is left
            // unenforced on purpose and `description()` says so, rather than the rule
            // reporting the field and calling the permission a violation.
            if is_1xx || is_204 {
                if let Some(value) = resp.headers.get("content-length") {
                    // Displayed, not decided on: the finding is already earned by the
                    // field being present, so a value no decoder accepts still gets
                    // shown rather than silently ending the check. `get` reads the
                    // first field line and that is all this is -- a second line is
                    // another instance of the same forbidden field, not a second
                    // finding, and nothing here is measuring a length.
                    let shown = crate::helpers::headers::field_line_as_written(value);
                    return Some(self.report(
                        ctx.severity,
                        status,
                        &format!(
                            "must not carry a Content-Length header field at any value, \
                             including 0, but carries \"{shown}\""
                        ),
                    ));
                }
            }

            // `Transfer-Encoding` is the same shape one document over, including the
            // 304 carve-out -- which is why this branch is also gated on the status set
            // above rather than on all three.
            // cite(RFC 9112 § 6.1): "A server MUST NOT send a Transfer-Encoding header field in any response with a status code of 1xx (Informational) or 204 (No Content)."
            // cite(RFC 9112 § 6.1): "Transfer-Encoding MAY be sent in a response to a HEAD request or in a 304 (Not Modified) response (Section 15.4.5 of [HTTP]) to a GET request, neither of which includes a message body, to indicate that the origin server would have applied a transfer coding to the message body if the request had been an unconditional GET."
            //
            // The version gate is *not* in that sentence -- it has no condition at all,
            // the way § 10.1.4's MUST for a `TE` connection option has none. It comes
            // from which document the sentence is in: RFC 9112 is HTTP/1.1's, and the
            // two later versions do not have the field, so on those the defect is the
            // field's presence and the status is beside the point.
            // `no_connection_specific_fields` reports it for both of them --
            // reporting it here as well would be two findings for one field.
            // cite(RFC 9113 § 8.2.2): "An endpoint MUST NOT generate an HTTP/2 message containing connection-specific header fields."
            // cite(RFC 9114 § 4.1): "Transfer codings (see Section 7 of [HTTP/1.1]) are not defined for HTTP/3; the Transfer-Encoding header field MUST NOT be used."
            //
            // HTTP/3 says the trailers half in its own words too, for interim responses,
            // which is why the check above needs no version gate of its own.
            // cite(RFC 9114 § 4.1): "Interim responses do not contain content or trailer sections."
            // The major digit decides which versions define transfer codings at
            // all; `http_version` owns the production that reads it.
            let version = resp.version.as_str();
            let a_version_that_has_the_field =
                !matches!(crate::http_version::major(version), Some(2 | 3));
            if (is_1xx || is_204)
                && a_version_that_has_the_field
                && resp.headers.contains_key("transfer-encoding")
            {
                return Some(self.report(
                    ctx.severity,
                    status,
                    "must not carry a Transfer-Encoding header field",
                ));
            }

            None
        };
        Vec::from_iter(finding())
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server No Body For 1xx, 204, 304")
    }

    fn description(&self) -> &'static str {
        "A `1xx (Informational)`, `204 (No Content)` or `304 (Not Modified)` response *\"is terminated by the end of the header section; it cannot contain content or trailers\"* — RFC 9110 writes that sentence once per status (§15.2, §15.3.5, §15.4.5), and RFC 9112 §6.3 restates it as framing: such a response ends at the first empty line *\"regardless of the header fields present in the message\"*.\n\n**Four findings, and they are not the same kind.** Two read what actually arrived, and are the violation itself: content octets in the response body, and a trailer section. Two read a header field, and are a violation of that field's own prohibition rather than evidence of a body — because no field can make one of these responses carry one.\n\n- **Content.** Any captured content octet is reported, for all three statuses. The count is of content in §6.4's sense, so chunk sizes and the trailer section are not in it. Of the two other rules that read the captured length for these statuses, one reaches its check only when a valid `Content-Length` is present and has handed these statuses over, and the other checked `1xx` alone and only when both request and response were HTTP/3; so a `204` answering with a chunked body and no declared length is seen here and was seen nowhere before.\n- **Trailers.** A trailer section is reported for all three statuses, whether or not it carries any fields: what the sentences forbid is the section. Which fields a trailer section may hold, when one is allowed, is `trailer_fields_valid`.\n- **`Content-Length`.** Reported on `1xx` and `204` only, at **any value including `0`** — §8.6's prohibition is on the field, not on a number. No value is parsed; `content_length_valid` owns the field's syntax.\n- **`Transfer-Encoding`.** Reported on `1xx` and `204` only, by RFC 9112 §6.1's matching MUST NOT.\n\n**The `304` is exempt from both field checks, by name, in both documents.** §8.6 says a server *\"MAY send a Content-Length header field in a 304 (Not Modified) response to a conditional GET request\"*, and RFC 9112 §6.1 says *\"Transfer-Encoding MAY be sent in a response to a HEAD request or in a 304 (Not Modified) response … to a GET request\"*. In a 304 both fields describe the `200` that was not sent. Each MAY carries a MUST NOT of its own — the value must equal what the unsent `200` would have had — and **that requirement is not enforced here and cannot be**: the octets it compares against were never transferred, so no single exchange holds them.\n\n**Versions.** §8.6 is RFC 9110's and applies to every version, so the `Content-Length` check is not gated. RFC 9112 §6.1 is HTTP/1.1's, and HTTP/2 and HTTP/3 do not have `Transfer-Encoding` at all — there the field's *presence* is the defect and the status is beside the point, so this rule declines: `no_connection_specific_fields` reports it on both, against whichever version carried the field section it is in.\n\n**`205 (Reset Content)` is not in this set.** Its prohibition (§15.3.6, *\"a server MUST NOT generate content in a 205 response\"*) is about generating content, and its framing is ordinary — so `Content-Length: 0` on a `205` is conforming where the same field on a `204` violates a MUST NOT. It needs its own rule, not a fourth status here."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.2",
                note: "Informational 1xx — \"A 1xx response is terminated by the end of the header section; it cannot contain content or trailers\"",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.3.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.5",
                note: "204 (No Content) — the same sentence, written again for this status",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.4.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.5",
                note: "304 (Not Modified) — the same sentence a third time. It forbids content and trailers, and says nothing against the two header fields that describe the 200 that was not sent",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.6"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6",
                note: "Content-Length — a MUST NOT on 1xx and 204 at any value, and a MAY on a 304 to a conditional GET. That MAY's own MUST NOT (the value must equal the unsent 200's content length) is undecidable from one exchange and is left unenforced",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("6.4.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-6.4.1",
                note: "Content Semantics — the summary this rule is named after. It is about content, not about header fields; taking it for a rule about fields is what put the 304 in front of two prohibitions that exempt it",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.3.6"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.6",
                note: "205 (Reset Content) — bodiless by a MUST NOT of its own, but with ordinary framing, so it is not reported by this rule and has none of its own",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("6.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3",
                note: "Message body length, item 1 — these responses end at the first empty line \"regardless of the header fields present\", which is why a field's presence is its own defect rather than evidence of a body",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("6.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1",
                note: "Transfer-Encoding — a MUST NOT on 1xx and 204, and a MAY on a 304 to a GET. HTTP/1.1's document, so the check does not run on later versions",
            },
            crate::rules::SpecRef {
                spec: "RFC 9113",
                section: Some("8.2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.2",
                note: "HTTP/2 — Transfer-Encoding is connection-specific and must not appear at all, whatever the status. No rule reports it yet",
            },
            crate::rules::SpecRef {
                spec: "RFC 9114",
                section: Some("4.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1",
                note: "HTTP/3 — transfer codings are not defined and the field must not be used; no_connection_specific_fields reports it. The same section repeats the trailers half for interim responses",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("204 — metadata about the resource, and nothing else"),
                snippet:
                    "HTTP/1.1 204 No Content\nETag: \"abc\"\nDate: Mon, 01 Jan 2024 00:00:00 GMT\n",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("304 — Content-Length describes the 200 that was not sent"),
                snippet: "HTTP/1.1 304 Not Modified\nETag: \"abc\"\nContent-Length: 1024\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("204 — the field is forbidden at any value, including 0"),
                snippet: "HTTP/1.1 204 No Content\nContent-Length: 0\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("100 — Transfer-Encoding on an interim response"),
                snippet: "HTTP/1.1 100 Continue\nTransfer-Encoding: chunked\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("304 — content, which no permission covers"),
                snippet: "HTTP/1.1 304 Not Modified\nETag: \"abc\"\n\nnot empty\n",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &NoBodyFor1xx204304;

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    /// Every fixture goes through here so a case can never be silent about the
    /// three inputs the rule reads: the status, the fields, and what arrived.
    fn make_tx(
        status: u16,
        version: &str,
        header_pairs: &[(&str, &str)],
        body_length: Option<u64>,
        trailer_pairs: Option<&[(&str, &str)]>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: version.into(),
            headers: crate::test_helpers::make_headers_from_pairs(header_pairs),
            body_length,
            trailers: trailer_pairs.map(crate::test_helpers::make_headers_from_pairs),
        });
        tx
    }

    fn run(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        crate::test_helpers::run_rule(
            &NoBodyFor1xx204304,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_severity(
                "no_body_for_1xx_204_304",
                "error",
            ),
        )
    }

    #[rstest]
    // --- the field checks, on the two statuses that have them ---
    #[case(204, "HTTP/1.1", &[("content-length", "10")], None, None, Some("Content-Length"))]
    // The value is irrelevant: § 8.6's MUST NOT is on the field. This case used to
    // assert the opposite.
    #[case(204, "HTTP/1.1", &[("content-length", "0")], None, None, Some("Content-Length"))]
    #[case(100, "HTTP/1.1", &[("content-length", "0")], None, None, Some("Content-Length"))]
    #[case(199, "HTTP/1.1", &[("content-length", "0")], None, None, Some("Content-Length"))]
    // No parse stands between the field and the finding any more.
    #[case(204, "HTTP/1.1", &[("content-length", "+5")], None, None, Some("Content-Length"))]
    #[case(204, "HTTP/1.1", &[("content-length", "5, 5")], None, None, Some("Content-Length"))]
    #[case(204, "HTTP/1.1", &[("transfer-encoding", "chunked")], None, None, Some("Transfer-Encoding"))]
    #[case(100, "HTTP/1.1", &[("transfer-encoding", "chunked")], None, None, Some("Transfer-Encoding"))]
    // --- the 304, which both prohibitions exempt by name ---
    #[case(304, "HTTP/1.1", &[("content-length", "1024")], None, None, None)]
    #[case(304, "HTTP/1.1", &[("transfer-encoding", "chunked")], None, None, None)]
    #[case(304, "HTTP/1.1", &[("content-length", "1024"), ("transfer-encoding", "gzip, chunked")], None, None, None)]
    // --- what arrived, which no status in the set may carry ---
    #[case(204, "HTTP/1.1", &[], Some(10), None, Some("content octets"))]
    #[case(304, "HTTP/1.1", &[], Some(10), None, Some("content octets"))]
    #[case(100, "HTTP/1.1", &[], Some(1), None, Some("content octets"))]
    // Chunked framing declares no length, so the captured count is the only
    // evidence there is -- and nothing in the tree looked at it without a
    // `Content-Length` to start from.
    #[case(304, "HTTP/1.1", &[("transfer-encoding", "chunked")], Some(10), None, Some("content octets"))]
    #[case(204, "HTTP/1.1", &[], Some(0), None, None)]
    #[case(204, "HTTP/1.1", &[], None, None, None)]
    // --- trailers: the word § 6.4.1's summary leaves out ---
    #[case(204, "HTTP/1.1", &[], None, Some(&[("expires", "0")][..]), Some("trailer section"))]
    #[case(304, "HTTP/1.1", &[], None, Some(&[("expires", "0")][..]), Some("trailer section"))]
    // A trailer section with no fields is still a trailer section.
    #[case(100, "HTTP/1.1", &[], None, Some(&[][..]), Some("trailer section"))]
    // --- versions: § 8.6 is every version's, RFC 9112 § 6.1 is HTTP/1.1's ---
    #[case(204, "HTTP/2.0", &[("content-length", "0")], None, None, Some("Content-Length"))]
    #[case(204, "HTTP/3.0", &[("content-length", "0")], None, None, Some("Content-Length"))]
    #[case(204, "HTTP/3.0", &[("transfer-encoding", "chunked")], None, None, None)]
    #[case(204, "HTTP/2.0", &[("transfer-encoding", "chunked")], None, None, None)]
    #[case(204, "HTTP/1.0", &[("transfer-encoding", "chunked")], None, None, Some("Transfer-Encoding"))]
    // --- outside the set ---
    #[case(200, "HTTP/1.1", &[("content-length", "10")], Some(10), None, None)]
    // 205 is bodiless by its own MUST NOT and has ordinary framing, so this rule
    // is not the one that judges it -- including the `Content-Length: 0` that a
    // 204 may not carry.
    #[case(205, "HTTP/1.1", &[("content-length", "0")], None, None, None)]
    #[case(205, "HTTP/1.1", &[], Some(10), None, None)]
    fn check_response_cases(
        #[case] status: u16,
        #[case] version: &str,
        #[case] header_pairs: &[(&str, &str)],
        #[case] body_length: Option<u64>,
        #[case] trailer_pairs: Option<&[(&str, &str)]>,
        #[case] expected_clause: Option<&str>,
    ) -> anyhow::Result<()> {
        let tx = make_tx(status, version, header_pairs, body_length, trailer_pairs);
        let violation = run(&tx);

        match expected_clause {
            Some(clause) => {
                let v = violation.unwrap_or_else(|| {
                    panic!(
                        "expected a finding for {status} {version} headers {header_pairs:?} \
                         body {body_length:?} trailers {trailer_pairs:?}"
                    )
                });
                assert_eq!(v.rule, "no_body_for_1xx_204_304");
                assert_eq!(v.severity, crate::lint::Severity::Error);
                // The clause that distinguishes this finding from the rule's
                // others. Asserting on the shared prefix would assert a rule
                // invariant and pass whichever branch fired.
                assert!(
                    v.message.contains(clause),
                    "finding did not name {clause:?}: {}",
                    v.message
                );
            }
            None => assert!(violation.is_none(), "unexpected violation: {violation:?}"),
        }
        Ok(())
    }

    /// What arrived outranks what was advertised: a 204 with both a forbidden
    /// field and real octets is reported for the octets, because that is the
    /// message's actual defect.
    #[test]
    fn content_is_reported_ahead_of_the_field_that_declared_it() {
        let tx = make_tx(204, "HTTP/1.1", &[("content-length", "10")], Some(10), None);
        let v = run(&tx).expect("expected a finding");
        assert!(v.message.contains("content octets"), "{}", v.message);
    }

    /// The finding shows the value it refuses to parse, so a `Content-Length` no
    /// decoder accepts still ends in front of an operator.
    #[test]
    fn a_non_utf8_content_length_is_still_reported() {
        let mut tx = make_tx(204, "HTTP/1.1", &[], None, None);
        tx.response.as_mut().expect("a response").headers.insert(
            hyper::header::CONTENT_LENGTH,
            hyper::header::HeaderValue::from_bytes(b"\xff\xfe").expect("a field value"),
        );
        let v = run(&tx).expect("expected a finding");
        assert!(v.message.contains("Content-Length"), "{}", v.message);
    }

    #[test]
    fn check_missing_response() {
        let tx = crate::test_helpers::make_test_transaction();
        assert!(run(&tx).is_none());
    }

    #[test]
    fn scope_is_server() {
        assert_eq!(NoBodyFor1xx204304.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "no_body_for_1xx_204_304");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    /// Builds a response transaction out of a published snippet, taking the
    /// content to be whatever follows the blank line that ends the header
    /// section.
    fn tx_from_snippet(snippet: &str) -> crate::http_transaction::HttpTransaction {
        let mut lines = snippet.split('\n');
        let status_line = lines.next().expect("a status line");
        let status: u16 = status_line
            .split(' ')
            .nth(1)
            .expect("a status code")
            .parse()
            .expect("a numeric status code");

        let mut headers = hyper::HeaderMap::new();
        let mut body_length = None;
        while let Some(line) = lines.next() {
            if line.is_empty() {
                let content: Vec<&str> = lines.collect();
                let joined = content.join("\n");
                body_length = Some(joined.trim_end_matches('\n').len() as u64);
                break;
            }
            let (name, value) = line.split_once(": ").expect("a field line");
            headers.insert(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).expect("a field name"),
                hyper::header::HeaderValue::from_str(value).expect("a field value"),
            );
        }

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers,
            body_length,
            trailers: None,
        });
        tx
    }

    /// Nothing runs a rule's own `examples()` through the engine, so a
    /// `Compliant` snippet the rule reports is published as guidance. The 304
    /// with a `Content-Length` is the one with teeth: it was a `NonCompliant`
    /// case here until § 8.6's MAY was read.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() -> anyhow::Result<()> {
        use crate::rules::Compliance;
        let rule = NoBodyFor1xx204304;
        let mut saw_a_finding = false;

        for ex in rule.examples() {
            let found = run(&tx_from_snippet(ex.snippet));
            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule reports its Compliant example {:?}: {found:?}",
                    ex.snippet
                ),
                Compliance::NonCompliant => {
                    found.unwrap_or_else(|| {
                        panic!("rule accepts its NonCompliant example {:?}", ex.snippet)
                    });
                    saw_a_finding = true;
                }
            }
        }

        assert!(saw_a_finding, "no published example produced a finding");
        Ok(())
    }
}
