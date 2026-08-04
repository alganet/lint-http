// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageResponseBodyLengthAccuracy;

impl Rule for MessageResponseBodyLengthAccuracy {
    fn id(&self) -> &'static str {
        "message_response_body_length_accuracy"
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
        // `message_content_length`'s, which owns the field's syntax on both
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
        // it: the octets it describes were never sent. `semantic_head_response_headers_match_get`
        // is the rule with two transactions to compare.
        let head_request = tx.request.method.eq_ignore_ascii_case("HEAD");
        let bodiless_status =
            (100..200).contains(&resp.status) || resp.status == 204 || resp.status == 304;
        if head_request || bodiless_status {
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

        // Compare to captured body length when available
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
        "When a response includes a `Content-Length` header, its numeric value MUST match the actual length in bytes of the captured response body after HTTP framing has been resolved (for example, after processing chunked transfer-coding), but not necessarily after any `Content-Encoding` (such as gzip) has been decoded. Mismatches indicate truncated or malformed responses and can lead to framing errors, truncated reads, or incorrect downstream handling. This rule validates that `Content-Length` (when present and syntactically valid) equals the captured body length recorded in the transaction."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.6"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6",
                note: "The `Content-Length` header field and rules about forwarding incorrect values",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("6.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3",
                note: "Message body length determination and framing (how body length is determined and handled)",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Length: 3\n\nabc",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(mismatched Content-Length)"),
                snippet: "HTTP/1.1 200 OK\nContent-Length: 10\n\nabc",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(invalid Content-Length)"),
                snippet: "HTTP/1.1 200 OK\nContent-Length: abc\n\nabc",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageResponseBodyLengthAccuracy;

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

        let rule = MessageResponseBodyLengthAccuracy;
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

        let rule = MessageResponseBodyLengthAccuracy;
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

        let rule = MessageResponseBodyLengthAccuracy;
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

        let rule = MessageResponseBodyLengthAccuracy;
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

        let rule = MessageResponseBodyLengthAccuracy;
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

        let rule = MessageResponseBodyLengthAccuracy;
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
        let rule = MessageResponseBodyLengthAccuracy;
        rule.check_transaction(
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
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
    /// `message_content_length` -- which owns the field's syntax and reports
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
        crate::test_helpers::enable_rule(&mut cfg, "message_response_body_length_accuracy");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn validate_rules_with_invalid_config_missing_severity() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_response_body_length_accuracy");
        // remove severity to simulate invalid config
        if let Some(toml::Value::Table(ref mut table)) =
            cfg.rules.get_mut("message_response_body_length_accuracy")
        {
            table.remove("severity");
        }

        let err = crate::rules::validate_rules(&cfg).expect_err("expected validation to fail");
        assert!(err.to_string().contains("Missing required 'severity'"));
    }
}
