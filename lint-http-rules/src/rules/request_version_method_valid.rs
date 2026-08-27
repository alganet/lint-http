// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Report a request that carries content under a method whose definition says
/// content has no meaning there.
///
/// Four methods qualify, and they do not qualify equally. GET, HEAD and DELETE
/// each close their section with the same SHOULD NOT and the same `unless`
/// clause; CONNECT is defined as a message that has no content at all. TRACE
/// belongs to the same family and is *not* checked here — `trace_method_echo`
/// already reports § 9.3.8's MUST NOT, and two rules reporting one sentence is
/// one rule too many.
///
/// The rule id carries "version" from an earlier plan to also judge a method
/// against `tx.request.version`. No such check exists and none is cited; the id
/// is kept because it is a published identifier, and `description()` says what
/// the rule actually measures.
pub struct RequestVersionMethodValid;

/// Whether the request message carries content.
///
/// Not the same question as "does the message declare a body", and the
/// difference is the finding: the sentences this rule enforces are about
/// *content*, and each says in its own first clause that framing is a separate
/// matter.
// cite(RFC 9110 § 9.3.1): "Although request message framing is independent of the method used, content received in a GET request has no generally defined semantics, cannot alter the meaning or target of the request"
//
// So `Transfer-Encoding: chunked` is not evidence of content. What that leaves
// is § 6.4's octet stream, measured once for every rule that asks this
// question — `trace_method_echo` asks it of the same paragraph family.
fn request_carries_content(req: &crate::http_transaction::RequestInfo) -> bool {
    crate::helpers::headers::content_evidence(&req.headers, req.body_length).is_some()
}

/// Whether the request message declares content in its header section.
///
/// CONNECT's question, and it has to be asked of the headers alone. § 9.3.6
/// gives the octets after a CONNECT request's header section no
/// version-independent meaning, so a field recorded per transaction cannot say
/// they are content; where the CONNECT succeeded they are the tunnel's own
/// traffic, and counting them would report every tunnel.
// cite(RFC 9110 § 9.3.6): "The interpretation of data sent after the header section of the CONNECT request message is specific to the version of HTTP in use."
fn request_declares_content(req: &crate::http_transaction::RequestInfo) -> bool {
    req.headers.contains_key("transfer-encoding")
        || crate::helpers::headers::declared_content_length(&req.headers).is_some_and(|n| n > 0)
}

impl Rule for RequestVersionMethodValid {
    fn id(&self) -> &'static str {
        "request_version_method_valid"
    }

    /// Every sentence this rule enforces addresses the client.
    // cite(RFC 9110 § 9.3.1): "A client SHOULD NOT generate content in a GET request unless it is made directly to an origin server that has previously indicated, in or out of band, that such a request has a purpose and will be adequately supported."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
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
            // Matched exactly, never case-folded. `get` is not the GET method, and
            // none of the sentences below say anything about it: an unrecognized
            // method has no defined content semantics, so there is nothing to
            // measure it against.
            // cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
            let method = tx.request.method.as_str();

            // One section per method, because the strength differs and the message
            // has to say which one it is. GET, HEAD and DELETE carry a SHOULD NOT
            // with an `unless`; CONNECT is a declaration about the message.
            // TRACE's MUST NOT is `trace_method_echo`'s.
            let sentence = match method {
                // cite(RFC 9110 § 9.3.1): "A client SHOULD NOT generate content in a GET request unless it is made directly to an origin server that has previously indicated, in or out of band, that such a request has a purpose and will be adequately supported."
                "GET" => "§ 9.3.1 says a client SHOULD NOT generate content in a GET request",
                // cite(RFC 9110 § 9.3.2): "A client SHOULD NOT generate content in a HEAD request unless it is made directly to an origin server that has previously indicated, in or out of band, that such a request has a purpose and will be adequately supported."
                "HEAD" => "§ 9.3.2 says a client SHOULD NOT generate content in a HEAD request",
                // cite(RFC 9110 § 9.3.5): "A client SHOULD NOT generate content in a DELETE request unless it is made directly to an origin server that has previously indicated, in or out of band, that such a request has a purpose and will be adequately supported."
                "DELETE" => "§ 9.3.5 says a client SHOULD NOT generate content in a DELETE request",

                // Not a requirement on the sender but a statement about the
                // message, so the finding is that the message contradicts its own
                // method's definition rather than that a modal was disobeyed.
                // cite(RFC 9110 § 9.3.6): "A CONNECT request message does not have content."
                "CONNECT" => {
                    return request_declares_content(&tx.request).then(|| self.violation(ctx.severity, "CONNECT request declares content in its header section; RFC 9110 § 9.3.6 defines a CONNECT request message as having none".into()));
                }

                _ => return None,
            };

            if !request_carries_content(&tx.request) {
                return None;
            }

            // The `unless` clause is a private agreement made "in or out of band",
            // which no observer of the exchange can confirm — but the sentence that
            // closes the same paragraph (identically in all three sections) says the
            // agreement is not something to rely on, and names why: the request
            // chain. So the finding stands and `description()` states the limit.
            // cite(RFC 9110 § 9.3.1): "An origin server SHOULD NOT rely on private agreements to receive content, since participants in HTTP communication are often unaware of intermediaries along the request chain."
            Some(self.violation(ctx.severity, format!(
                    "{} request carries content; RFC 9110 {}, and content received in one has no generally defined semantics",
                    method, sentence
                )))
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "Reports a request that carries content under a method whose definition gives content no meaning there. RFC 9110 says it about GET (§9.3.1), HEAD (§9.3.2) and DELETE (§9.3.5) in three identical paragraphs: content in such a request \"has no generally defined semantics, cannot alter the meaning or target of the request, and might lead some implementations to reject the request and close the connection because of its potential as a request smuggling attack\". CONNECT (§9.3.6) is stated differently and reported differently — see below.\n\n**A SHOULD NOT with a condition this rule cannot check.** The GET/HEAD/DELETE sentences end \"unless it is made directly to an origin server that has previously indicated, in or out of band, that such a request has a purpose and will be adequately supported\". An agreement reached out of band leaves no trace in the message, so a request under such an agreement is reported like any other. The exemption is not simply ignored, though: the next sentence in each of those three paragraphs says \"An origin server SHOULD NOT rely on private agreements to receive content, since participants in HTTP communication are often unaware of intermediaries along the request chain\" — and a request this tool observed at a proxy has, by construction, an intermediary in its chain.\n\n**CONNECT is a different kind of finding.** §9.3.6 states \"A CONNECT request message does not have content.\" — a definition, not a modal a sender disobeys. So the report is that the message contradicts its own method's definition. It is also the one method judged on its header section alone: §9.3.6 says \"The interpretation of data sent after the header section of the CONNECT request message is specific to the version of HTTP in use\", so a per-transaction octet count carries no version-independent claim that those octets are content — and where the CONNECT succeeded they are the tunnel's own traffic.\n\n**Content, not framing.** Each of the three paragraphs opens \"Although request message framing is independent of the method used\", so a `Transfer-Encoding` is not by itself content: a chunked request whose first chunk is the terminator carries none, and over HTTP/2 and HTTP/3 content arrives with no framing field at all. Where a body was captured, its octet count is what decides; otherwise the request's own `Content-Length` is.\n\n**Not checked here.** TRACE's §9.3.8 MUST NOT is `trace_method_echo`'s, so enabling this rule alone leaves TRACE unreported. OPTIONS may carry content (§9.3.7), which comes with a MUST on the `Content-Type` describing it — that is `options_method_capabilities`'s finding, not this rule's. Neither does any other method: a method this specification does not define has no content semantics to contradict. And nothing here reads `tx.request.version`, despite the id."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("9.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1",
                note: "Methods overview — the method token is case-sensitive, which is why the four names below are matched exactly and a lowercase `get` is not a GET",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("9.3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.1",
                note: "GET — the SHOULD NOT, its `unless` clause, and the sentence that declines to rely on the private agreement the clause describes. Also the statement that framing is independent of the method, which is why a Transfer-Encoding alone is not content",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("9.3.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.2",
                note: "HEAD — the same paragraph, word for word",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("9.3.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.5",
                note: "DELETE — the same paragraph again",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("9.3.6"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6",
                note: "CONNECT — a definition rather than a modal, and the sentence that makes the octets after the header section tunnel payload instead of content",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.6"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6",
                note: "Content-Length as the amount of data enclosed — the fallback evidence when no body was captured",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet:
                    "POST /upload HTTP/1.1\nHost: example.com\nContent-Length: 123\n\n<binary data>",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(DELETE with no body)"),
                snippet: "DELETE /resource/42 HTTP/1.1\nHost: example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(GET with a body)"),
                snippet: "GET /search HTTP/1.1\nHost: example.com\nContent-Length: 5\n\nhello",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(CONNECT declaring content)"),
                snippet: "CONNECT server.example.com:443 HTTP/1.1\nHost: server.example.com:443\nContent-Length: 1\n\nx",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &RequestVersionMethodValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// One constructor for every fixture, so `body_length` — the field that
    /// decides the finding — is always stated rather than defaulted.
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

    fn check(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        let rule = RequestVersionMethodValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        crate::test_helpers::run_rule(
            &rule,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
    }

    #[rstest]
    #[case("GET", vec![], None, false)]
    #[case("GET", vec![("content-length", "0")], None, false)]
    #[case("GET", vec![("content-length", "10")], None, true)]
    #[case("HEAD", vec![("content-length", "1")], None, true)]
    #[case("DELETE", vec![("content-length", "1")], None, true)]
    #[case("CONNECT", vec![("content-length", "1")], None, true)]
    #[case("CONNECT", vec![("transfer-encoding", "chunked")], None, true)]
    #[case("CONNECT", vec![("content-length", "0")], None, false)]
    #[case("POST", vec![("content-length", "1")], Some(1), false)]
    #[case("PUT", vec![("transfer-encoding", "chunked")], Some(9), false)]
    #[case("OPTIONS", vec![("content-length", "5")], Some(5), false)]
    // TRACE is `trace_method_echo`'s, across all three signals.
    #[case("TRACE", vec![("content-length", "1")], Some(1), false)]
    fn method_body_cases(
        #[case] method: &str,
        #[case] headers: Vec<(&str, &str)>,
        #[case] body_length: Option<u64>,
        #[case] expect_violation: bool,
    ) {
        let tx = make_tx(method, headers, body_length);
        let v = check(&tx);

        if expect_violation {
            assert!(v.is_some(), "expected violation for {}", method);
        } else {
            assert!(v.is_none(), "unexpected violation for {}: {:?}", method, v);
        }
    }

    /// § 9.1: the method token is case-sensitive. A lowercase `get` is not the
    /// GET method, so no sentence in § 9.3 measures its content.
    #[rstest]
    #[case("get")]
    #[case("Get")]
    #[case("delete")]
    #[case("connect")]
    fn lowercase_method_names_are_not_the_methods(#[case] method: &str) {
        let tx = make_tx(method, vec![("content-length", "10")], Some(10));
        assert!(check(&tx).is_none(), "reported {} against § 9.3", method);
    }

    /// Framing is independent of the method: a chunked request whose only chunk
    /// is the terminator carries no content, and the octet count says so.
    #[rstest]
    #[case(Some(0), false)]
    #[case(Some(5), true)]
    fn chunked_request_is_judged_by_its_octets(
        #[case] body_length: Option<u64>,
        #[case] expect_violation: bool,
    ) {
        let tx = make_tx(
            "DELETE",
            vec![("transfer-encoding", "chunked")],
            body_length,
        );
        assert_eq!(check(&tx).is_some(), expect_violation);
    }

    /// Content with no framing field at all — the HTTP/2 and HTTP/3 shape.
    #[test]
    fn captured_octets_alone_are_content() {
        let tx = make_tx("GET", vec![], Some(7));
        assert!(check(&tx).is_some());
    }

    /// § 5.3 makes several `Content-Length` lines one value, and RFC 9112 § 6.3
    /// makes `5, 5` one value of five. Reading the first line alone missed both.
    #[rstest]
    #[case(vec![("content-length", "5, 5")], true)]
    #[case(vec![("content-length", "0"), ("content-length", "0")], false)]
    fn content_length_is_read_as_one_value(
        #[case] headers: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) {
        let tx = make_tx("GET", headers, None);
        assert_eq!(check(&tx).is_some(), expect_violation);
    }

    /// A CONNECT is judged on its header section: § 9.3.6 gives the octets
    /// after it no version-independent meaning as content.
    #[test]
    fn connect_ignores_captured_octets() {
        let tx = make_tx("CONNECT", vec![], Some(4096));
        assert!(check(&tx).is_none());
    }

    /// A `Content-Length` that leaves no number leaves this rule nothing to
    /// measure; `content_length_valid` is where the field's own syntax is
    /// reported.
    #[rstest]
    #[case("not-a-number")]
    #[case("")]
    #[case("   ")]
    #[case(&"9".repeat(100))]
    fn unreadable_content_length_is_ignored(#[case] value: &str) {
        let tx = make_tx("GET", vec![("content-length", value)], None);
        assert!(check(&tx).is_none(), "reported on Content-Length {value:?}");
    }

    /// The message names the section whose sentence produced it, and the two
    /// kinds of finding read differently — a modal the client disobeyed versus
    /// a definition the message contradicts.
    #[test]
    fn violation_messages_name_their_sentence() {
        let v = check(&make_tx("GET", vec![("content-length", "10")], None)).unwrap();
        assert!(v.message.contains("§ 9.3.1"), "{}", v.message);
        assert!(v.message.contains("SHOULD NOT"), "{}", v.message);

        let v2 = check(&make_tx("HEAD", vec![("content-length", "1")], None)).unwrap();
        assert!(v2.message.contains("§ 9.3.2"), "{}", v2.message);

        let v3 = check(&make_tx("CONNECT", vec![("content-length", "1")], None)).unwrap();
        assert!(v3.message.contains("§ 9.3.6"), "{}", v3.message);
        assert!(!v3.message.contains("SHOULD NOT"), "{}", v3.message);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "request_version_method_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
