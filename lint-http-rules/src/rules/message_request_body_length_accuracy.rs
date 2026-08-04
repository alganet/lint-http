// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageRequestBodyLengthAccuracy;

impl Rule for MessageRequestBodyLengthAccuracy {
    fn id(&self) -> &'static str {
        "message_request_body_length_accuracy"
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
        let req = &tx.request;

        // This rule used to transcribe the whole `Content-Length` grammar
        // inline -- `1*DIGIT`, the u128 ceiling, the multiple-values-differ
        // check, the non-UTF8 branch -- and emit findings for each, with
        // message strings byte-identical to `message_content_length`'s. That
        // rule owns the field's syntax, on both sides, and delegates to
        // `validate_content_length`. So every malformed value here produced two
        // identical findings for one defect.
        //
        // Worse, the copy had fallen behind the original. § 6.3 makes a
        // comma-separated list valid when every value parses and they all
        // agree, and says what such a message means; the helper implements
        // that, and the inline copy rejected `Content-Length: 5, 5` as an
        // invalid value.
        // cite(RFC 9112 § 6.3): "If a message is received without Transfer-Encoding and with an invalid Content-Length header field, then the message framing is invalid and the recipient MUST treat it as an unrecoverable error, unless the field value can be successfully parsed as a comma-separated list (Section 5.6.1 of [HTTP]), all values in the list are valid, and all values in the list are the same (in which case, the message is processed with that single value used as the Content-Length field value)."
        //
        // Nothing is re-quoted here on purpose. A syntax error means there is
        // no number to compare a body against, so this rule declines and
        // `message_content_length` makes the report.
        // cite(RFC 9112 § 6.3): "The length of a message body is determined by one of the following (in order of precedence)"
        let declared = crate::helpers::headers::validate_content_length(&req.headers).ok()??;

        // The sentence that licenses this entire rule carries a condition the
        // rule did not honour. § 6.3's sixth item is what makes a declared
        // length mean anything about a body -- and it applies only *without*
        // Transfer-Encoding:
        // cite(RFC 9112 § 6.3): "If a valid Content-Length header field is present without Transfer-Encoding, its decimal value defines the expected message body length in octets."
        //
        // When both are present, the number this rule was comparing is one the
        // specification says to disregard, and the body length comes from
        // decoding the transfer coding instead:
        // cite(RFC 9112 § 6.3): "If a message is received with both a Transfer-Encoding and a Content-Length header field, the Transfer-Encoding overrides the Content-Length."
        // cite(RFC 9112 § 6.3): "If a Transfer-Encoding header field is present and the chunked transfer coding (Section 7.1) is the final encoding, the message body length is determined by reading and decoding the chunked data until the transfer coding indicates the data is complete."
        //
        // So `Content-Length: 10` beside `Transfer-Encoding: chunked` and a
        // three-octet chunked body was reported as an inaccurate length, when
        // the length was never the operative one. The message is certainly
        // suspect -- § 6.3 calls it a possible smuggling attempt -- and
        // `message_content_length_vs_transfer_encoding` is the rule that says
        // so. This one has nothing left to measure.
        //
        // Presence is all that matters here, not what the field contains: the
        // overriding is unconditional on the transfer coding being valid or
        // even parseable. § 6.2 states the condition from the other end, and
        // makes sending both a MUST NOT in its own right -- which is
        // `message_content_length_vs_transfer_encoding`'s finding, not this
        // rule's.
        // cite(RFC 9112 § 6.2): "When a message does not have a Transfer-Encoding header field, a Content-Length header field (Section 8.6 of [HTTP]) can provide the anticipated size, as a decimal number of octets, for potential content."
        // cite(RFC 9112 § 6.2): "A sender MUST NOT send a Content-Length header field in any message that contains a Transfer-Encoding header field."
        if req.headers.contains_key(hyper::header::TRANSFER_ENCODING) {
            return None;
        }

        // The comparison itself. What makes a difference worth reporting is not
        // arithmetic: § 6.2 says this number is the framing, and § 6.3 says a
        // recipient that does not receive that many octets has an incomplete
        // message on its hands and must close the connection. A request whose
        // declared length does not match the octets that arrived is one of
        // those, whichever way the difference runs.
        // cite(RFC 9112 § 6.2): "For messages that do include content, the Content-Length field value provides the framing information necessary for determining where the data (and message) ends."
        // cite(RFC 9112 § 6.3): "If the sender closes the connection or the recipient times out before the indicated number of octets are received, the recipient MUST consider the message to be incomplete and close the connection."
        //
        // `body_length` counts the octets that streamed through, with the
        // transfer coding already resolved and any `Content-Encoding` left
        // alone -- which is the same thing `Content-Length` counts, so the two
        // are comparable as they stand. It is `None` when nothing was captured,
        // and then there is nothing to compare.
        //
        // `request_body_over_limit` is deliberately *not* consulted, and that
        // was checked rather than assumed. It reads like a reason to distrust
        // the length -- a truncated capture -- but neither producer makes it
        // one: the streaming path counts every octet that passes and truncates
        // only the retained prefix, so the total stays exact; the one buffered
        // path records no body at all when it rejects an over-limit request, so
        // the length is `None` and this rule has already declined. Skipping on
        // the flag would lose real findings and prevent none.
        // cite(RFC 9110 § 8.6): "The "Content-Length" header field indicates the associated representation's data length as a decimal non-negative integer number of octets."
        if let Some(body_len) = req.body_length {
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
        "Checks that a request's `Content-Length` matches the number of body octets actually observed. RFC 9112 §6.2 makes that number the framing — \"the Content-Length field value provides the framing information necessary for determining where the data (and message) ends\" — and §6.3 says a recipient that does not receive that many octets \"MUST consider the message to be incomplete and close the connection\". A mismatch is that message.\n\n**Only when there is no `Transfer-Encoding`.** §6.3 licenses the comparison in exactly those terms: \"If a valid Content-Length header field is present *without Transfer-Encoding*, its decimal value defines the expected message body length in octets.\" When both fields are present the Transfer-Encoding overrides, and the declared length is a number the specification says to disregard — so this rule stays silent. Sending both is its own MUST NOT (§6.2) and `message_content_length_vs_transfer_encoding` reports it.\n\n**Syntax belongs to another rule.** A `Content-Length` that is not a valid `1*DIGIT` — or whose field lines disagree, or which no integer can represent — leaves no number to compare, so this rule declines and `message_content_length` reports it. That rule is also where §6.3's comma-list allowance lives: `Content-Length: 3, 3` is one value of three, not a malformed field.\n\n**What the comparison is against.** The recorded length counts the octets that streamed through with the transfer coding resolved and any `Content-Encoding` left encoded — which is what `Content-Length` counts too, so the two are directly comparable. Where no body was captured, nothing is claimed."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("6.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3",
                note: "Message body length — item 6 is what licenses this rule at all, and its condition is 'without Transfer-Encoding'; item 3 is why a message carrying both is measured by neither",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("6.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6.2",
                note: "Content-Length as framing — why a mismatch matters rather than merely differing. Also the MUST NOT against sending it beside Transfer-Encoding, which is another rule's finding",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.6"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6",
                note: "Where the field and its `1*DIGIT` grammar are actually defined — the syntax itself is `message_content_length`'s subject, not this rule's",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "POST /upload HTTP/1.1\nHost: example.com\nContent-Length: 3\n\nabc",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(a comma list of equal values is one value)"),
                snippet: "POST /upload HTTP/1.1\nHost: example.com\nContent-Length: 3, 3\n\nabc",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(Transfer-Encoding overrides, so nothing here is measured)"),
                snippet: "POST /upload HTTP/1.1\nHost: example.com\nContent-Length: 10\nTransfer-Encoding: chunked\n\nabc",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the request is incomplete)"),
                snippet: "POST /upload HTTP/1.1\nHost: example.com\nContent-Length: 10\n\nabc",
            },
            // The published `Content-Length: abc` example was labelled
            // "(invalid Content-Length)" and is `message_content_length`'s
            // finding, not this rule's -- it is gone rather than relabelled,
            // because this rule reports nothing for it.
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageRequestBodyLengthAccuracy;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn matching_content_length_and_body_no_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request = crate::http_transaction::RequestInfo {
            method: "POST".into(),
            uri: "http://example/".into(),
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("content-length", "3")]),
            body_length: Some(3),
            trailers: None,
        };

        let rule = MessageRequestBodyLengthAccuracy;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn mismatching_content_length_and_body_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request = crate::http_transaction::RequestInfo {
            method: "POST".into(),
            uri: "http://example/".into(),
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("content-length", "10")]),
            body_length: Some(3),
            trailers: None,
        };

        let rule = MessageRequestBodyLengthAccuracy;
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
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request = crate::http_transaction::RequestInfo {
            method: "POST".into(),
            uri: "http://example/".into(),
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[]),
            body_length: Some(5),
            trailers: None,
        };

        let rule = MessageRequestBodyLengthAccuracy;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn content_length_present_but_no_captured_body_no_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request = crate::http_transaction::RequestInfo {
            method: "POST".into(),
            uri: "http://example/".into(),
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("content-length", "3")]),
            body_length: None,
            trailers: None,
        };

        let rule = MessageRequestBodyLengthAccuracy;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn multiple_identical_content_length_headers_no_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        use hyper::header::HeaderValue;
        hm.append("content-length", HeaderValue::from_static("10"));
        hm.append("content-length", HeaderValue::from_static("10"));
        tx.request = crate::http_transaction::RequestInfo {
            method: "POST".into(),
            uri: "http://example/".into(),
            version: "HTTP/1.1".into(),
            headers: hm,
            body_length: Some(10),
            trailers: None,
        };

        let rule = MessageRequestBodyLengthAccuracy;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn whitespace_in_content_length_is_accepted() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request = crate::http_transaction::RequestInfo {
            method: "POST".into(),
            uri: "http://example/".into(),
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("content-length", "  3  ")]),
            body_length: Some(3),
            trailers: None,
        };

        let rule = MessageRequestBodyLengthAccuracy;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    fn req_with(
        headers: &[(&str, &str)],
        body_length: Option<u64>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request = crate::http_transaction::RequestInfo {
            method: "POST".into(),
            uri: "http://example/".into(),
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(headers),
            body_length,
            trailers: None,
        };
        tx
    }

    fn run(tx: &crate::http_transaction::HttpTransaction) -> Option<crate::lint::Violation> {
        let rule = MessageRequestBodyLengthAccuracy;
        rule.check_transaction(
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    /// Every published snippet is run through the rule, with the body length
    /// taken from the snippet's own body rather than asserted separately --
    /// which is the only way these examples mean anything, since the whole
    /// finding is a comparison between the two.
    ///
    /// One of the three used to be `Content-Length: abc`, labelled "(invalid
    /// Content-Length)". That is `message_content_length`'s finding, and this
    /// rule now reports nothing for it, so it is gone rather than relabelled.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, Rule as _};
        let rule = MessageRequestBodyLengthAccuracy;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        for ex in rule.examples() {
            let (head, body) = ex
                .snippet
                .split_once("\n\n")
                .unwrap_or_else(|| panic!("example has no body: {:?}", ex.snippet));
            let pairs: Vec<(&str, &str)> = head
                .lines()
                .skip(1)
                .map(|l| {
                    l.split_once(": ")
                        .unwrap_or_else(|| panic!("not a header line: {l:?}"))
                })
                .collect();

            let mut tx = crate::test_helpers::make_test_transaction();
            tx.request.method = "POST".into();
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&pairs);
            // The snippets show the body as it appears on the wire. For the
            // chunked example that is not the decoded length, but that example
            // is never measured -- the Transfer-Encoding sees to it.
            tx.request.body_length = Some(body.len() as u64);

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

    /// § 6.3's sixth item -- the sentence that gives a declared length any
    /// bearing on a body -- applies only *without* Transfer-Encoding. With one
    /// present, the Transfer-Encoding overrides and the number this rule
    /// compares is one the specification says to disregard. The message is
    /// still suspect, and `message_content_length_vs_transfer_encoding` is the
    /// rule that says so.
    #[rstest]
    #[case("chunked")]
    #[case("gzip, chunked")]
    // Presence is what overrides, not validity: a transfer coding this rule
    // could make nothing of still displaces the Content-Length.
    #[case("nonsense")]
    #[case("")]
    fn transfer_encoding_overrides_and_leaves_nothing_to_measure(#[case] te: &str) {
        let tx = req_with(
            &[("content-length", "10"), ("transfer-encoding", te)],
            Some(3),
        );
        assert!(
            run(&tx).is_none(),
            "Transfer-Encoding: {te:?} overrides the Content-Length"
        );
    }

    /// Without one, the comparison is exactly what § 6.3 licenses.
    #[test]
    fn without_transfer_encoding_the_comparison_stands() {
        let tx = req_with(&[("content-length", "10")], Some(3));
        assert!(run(&tx).is_some_and(|v| v.message.contains("does not match")));
    }

    /// A malformed value leaves no number to compare a body against, so this
    /// rule declines and `message_content_length` -- which owns the field's
    /// syntax on both sides and reports these with the same message strings --
    /// makes the report. These five used to be duplicated here.
    #[rstest]
    #[case("abc")]
    #[case("+1")]
    #[case("")]
    #[case("340282366920938463463374607431768211456")]
    fn a_malformed_value_is_left_to_the_rule_that_owns_the_syntax(#[case] cl: &str) {
        let tx = req_with(&[("content-length", cl)], Some(3));
        assert!(run(&tx).is_none(), "{cl:?} is the syntax rule's finding");
    }

    /// The same, for values that disagree across field lines.
    #[test]
    fn values_that_disagree_are_left_to_the_syntax_rule() {
        use hyper::header::HeaderValue;
        let mut tx = req_with(&[], Some(10));
        let mut hm = hyper::HeaderMap::new();
        hm.append("content-length", HeaderValue::from_static("10"));
        hm.append("content-length", HeaderValue::from_static("20"));
        tx.request.headers = hm;
        assert!(run(&tx).is_none());
    }

    /// A value the sending side never wrote as a violation: § 6.3 makes a
    /// comma-separated list valid when every value parses and they all agree,
    /// and says the message is processed with that single value. The inline
    /// copy of the grammar rejected this; the helper has always accepted it.
    #[rstest]
    #[case("3, 3", Some(3), false)]
    #[case("3, 3", Some(4), true)]
    fn a_comma_list_of_equal_values_is_one_value(
        #[case] cl: &str,
        #[case] body: Option<u64>,
        #[case] expect: bool,
    ) {
        let tx = req_with(&[("content-length", cl)], body);
        assert_eq!(run(&tx).is_some(), expect, "{cl:?} vs {body:?}");
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_request_body_length_accuracy");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn validate_rules_with_invalid_config_missing_severity() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_request_body_length_accuracy");
        // remove severity to simulate invalid config
        if let Some(toml::Value::Table(ref mut table)) =
            cfg.rules.get_mut("message_request_body_length_accuracy")
        {
            table.remove("severity");
        }

        let err = crate::rules::validate_rules(&cfg).expect_err("expected validation to fail");
        assert!(err.to_string().contains("Missing required 'severity'"));
    }
}
