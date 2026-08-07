// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerContentTypePresent;

impl Rule for ServerContentTypePresent {
    fn id(&self) -> &'static str {
        "server_content_type_present"
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
        let Some(resp) = &tx.response else {
            return None;
        };

        // The responses that carry no content, and so cannot be missing a
        // header field that describes content. The list had three entries and
        // needed six.
        // cite(RFC 9112 § 6.3): "Any response to a HEAD request and any response with a 1xx (Informational), 204 (No Content), or 304 (Not Modified) status code is always terminated by the first empty line after the header fields, regardless of the header fields present in the message, and thus cannot contain a message body or trailer section."
        let status = resp.status;
        let bodiless_status = (100..200).contains(&status) || status == 204 || status == 304;

        // 205 is not in § 6.3's item 1, and is bodiless all the same -- its own
        // status definition says so in a MUST NOT. A 205 declaring a
        // Content-Length was reported for omitting a Content-Type it has
        // nothing to describe.
        // cite(RFC 9110 § 15.3.6): "Since the 205 status code implies that no additional content will be provided, a server MUST NOT generate content in a 205 response."
        let reset_content = status == 205;

        // A HEAD response carries no content by definition, so § 8.3's
        // condition -- "a message containing content" -- is not met however
        // large the resource is. Whether it *should* still carry the
        // Content-Type a GET would have sent is a different sentence (§ 9.3.2's
        // same-header-fields SHOULD) and a different rule's finding:
        // `semantic_head_response_headers_match_get` compares the two
        // transactions, and its configurable header list already names
        // `content-type`.
        // cite(RFC 9110 § 9.3.2): "The HEAD method is identical to GET except that the server MUST NOT send content in the response."
        let head_request = tx.request.method.eq_ignore_ascii_case("HEAD");

        // And a 2xx to CONNECT is a tunnel: the octets after the header section
        // are not content and no media type describes them.
        // cite(RFC 9112 § 6.3): "Any 2xx (Successful) response to a CONNECT request implies that the connection will become a tunnel immediately after the empty line that concludes the header fields."
        let tunnelling =
            tx.request.method.eq_ignore_ascii_case("CONNECT") && (200..300).contains(&status);

        if bodiless_status || reset_content || head_request || tunnelling {
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
        let has_content = match resp.body_length {
            Some(n) => n > 0,
            None => {
                let declared = crate::helpers::headers::validate_content_length(&resp.headers)
                    .ok()
                    .flatten();
                declared.is_some_and(|n| n > 0)
                    || resp.headers.contains_key(hyper::header::TRANSFER_ENCODING)
            }
        };

        // cite(RFC 9110 § 8.3): "Content-Type = media-type"
        if has_content {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Response contains content but no Content-Type header".into(),
            });
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Content-Type Present")
    }

    fn description(&self) -> &'static str {
        "This rule ensures that responses which likely contain a body include a `Content-Type` header. This helps downstream components and user agents interpret the response bytes correctly.\n\nThe rule considers a response to likely have a body when any of:\n- `Content-Length` is present and > 0\n- `Transfer-Encoding` is present\n- Response status is 2xx and neither `Content-Length` nor `Transfer-Encoding` is present"
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3",
                note: "Content-Type header",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("6"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6",
                note: "Message body length rules",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("Response"),
                snippet:
                    "HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8\nContent-Length: 123",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Response"),
                snippet: "HTTP/1.1 200 OK\nContent-Length: 123\n# Missing Content-Type",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ServerContentTypePresent;

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
        let rule = ServerContentTypePresent;

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(header_pairs.as_slice()),

            body_length: None,
            trailers: None,
        });

        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );

        if expect_violation {
            assert!(violation.is_some());
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
            trailers: None,
        });
        tx
    }

    fn run(tx: &crate::http_transaction::HttpTransaction) -> Option<crate::lint::Violation> {
        let rule = ServerContentTypePresent;
        rule.check_transaction(
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
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
        let rule = ServerContentTypePresent;
        let tx = crate::test_helpers::make_test_transaction();
        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(violation.is_none());
    }
}
