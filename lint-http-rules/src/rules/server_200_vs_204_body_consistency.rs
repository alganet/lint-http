// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct Server200Vs204BodyConsistency;

impl Server200Vs204BodyConsistency {
    /// The one place a finding is built. Both call sites say the same thing about
    /// the message and differ only in what showed the content to be empty, so
    /// `evidence` is the clause that distinguishes them and the clause a test keys
    /// on.
    fn report(&self, severity: crate::lint::Severity, evidence: &str) -> Violation {
        // This is the sentence the whole rule rests on, and it is worth reading
        // twice. Its modal is "ought to", weaker than a SHOULD; its condition is
        // about the *request*, and no field on the wire records whether a client
        // preferred an empty success. So the finding is advice with an unobservable
        // premise, which is what the message says and what `description()` opens
        // with.
        // cite(RFC 9110 § 15.3.1): "If some aspect of the request indicates a preference for no content upon success, the origin server ought to send a 204 (No Content) response instead."
        //
        // The alternative the advice names, and why it is one: a 204 says the same
        // "succeeded" as a 200 and says the emptiness on purpose.
        // cite(RFC 9110 § 15.3.5): "The 204 (No Content) status code indicates that the server has successfully fulfilled the request and that there is no additional content to send in the response content."
        // cite(RFC 9110 § 15.3.5): "A 204 response is terminated by the end of the header section; it cannot contain content or trailers."
        Violation {
            rule: self.id().into(),
            severity,
            message: format!(
                "200 (OK) response carries no content ({evidence}); RFC 9110 §15.3.1 says an origin server ought to send 204 (No Content) instead if some aspect of the request indicates a preference for no content upon success. That condition is about the request and is not observable here, so this is advice: a 200 whose framing says the content is empty violates nothing"
            ),
        }
    }
}

impl Rule for Server200Vs204BodyConsistency {
    fn id(&self) -> &'static str {
        "server_200_vs_204_body_consistency"
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

        // Both sentences this rule rests on are written for one status code. The
        // first is the expectation, and reading it to the end matters: the case
        // this rule reports -- framing that says the content is empty -- is the
        // exception the expectation carves out, not a breach of it. What licenses
        // a finding at all is the second sentence, quoted at the report below.
        // cite(RFC 9110 § 15.3.1): "The 200 (OK) status code indicates that the request has succeeded."
        // cite(RFC 9110 § 15.3.1): "Aside from responses to CONNECT, a 200 response is expected to contain message content unless the message framing explicitly indicates that the content has zero length."
        if resp.status != 200 {
            return None;
        }

        // The method token is compared byte for byte in both exemptions below. A
        // fold would exempt `head` and `connect`, which are not those methods and
        // are not what the sentences quoted there are about.
        // cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
        //
        // A response to HEAD cannot carry content whatever the server intended, so
        // its emptiness is not evidence that 204 was meant.
        // cite(RFC 9110 § 9.3.2): "The HEAD method is identical to GET except that the server MUST NOT send content in the response."
        // cite(RFC 9110 § 6.4.1): "Responses to the HEAD request method (Section 9.3.2) never include content; the associated response header fields indicate only what their values would have been if the request method had been GET (Section 9.3.1)."
        if tx.request.method == "HEAD" {
            return None;
        }

        // A 200 answering CONNECT is the successful end of the handshake: the tunnel
        // starts where the content would have been. The advice this rule gives would
        // be actively wrong here, because a 204 does not open a tunnel -- and the
        // first sentence quoted above excludes CONNECT before any of that.
        // cite(RFC 9110 § 15.3.1): "For CONNECT, there is no content because the successful result is a tunnel, which begins immediately after the 200 response header section."
        // cite(RFC 9110 § 6.4.1): "2xx (Successful) responses to a CONNECT request method (Section 9.3.6) switch the connection to tunnel mode instead of having content."
        if tx.request.method == "CONNECT" {
            return None;
        }

        // A declared length is the message's framing only when nothing overrides it.
        // The sentence is HTTP/1.1's, and so is the field: a `Transfer-Encoding` is
        // only meaningful in the version that defines it, which is the only version
        // that can reach this branch with the field present.
        //
        // Skipping the *field* is all this buys. The captured octet count below is
        // still evidence, and consulting it is the only way a chunked 200 with an
        // empty body is seen at all -- chunked framing is precisely the case that
        // declares no length.
        // cite(RFC 9112 § 6.3): "If a message is received with both a Transfer-Encoding and a Content-Length header field, the Transfer-Encoding overrides the Content-Length."
        if !resp.headers.contains_key("transfer-encoding") {
            // cite(RFC 9112 § 6.3): "If a valid Content-Length header field is present without Transfer-Encoding, its decimal value defines the expected message body length in octets."
            // cite(RFC 9110 § 8.6): "The "Content-Length" header field indicates the associated representation's data length as a decimal non-negative integer number of octets."
            match crate::helpers::headers::validate_content_length(&resp.headers) {
                // Zero octets, said by the sender rather than counted by the capture.
                Ok(Some(0)) => return Some(self.report(config.severity, "Content-Length: 0")),
                // A declared length above zero is content, and the expectation quoted
                // at the status gate is met.
                Ok(Some(_)) => return None,
                // No declared length: the capture's count is the remaining evidence.
                Ok(None) => {}
                // An invalid `Content-Length` is a framing error, not a statement that
                // the content is empty, and `message_content_length` is the rule that
                // reports it. There is nothing left here to conclude "no content" from,
                // so this declines rather than falling through to the captured count.
                Err(_) => return None,
            }
        }

        match resp.body_length {
            // Nothing was declared, and the capture counted no content octets. The
            // count is of content, not of framing: chunk sizes and the trailer section
            // are not in it.
            // cite(RFC 9110 § 6.4): "This abstract definition of content reflects the data after it has been extracted from the message framing."
            Some(0) => Some(self.report(config.severity, "captured length 0")),
            // Content was counted.
            Some(_) => None,
            // Neither the sender nor the capture says how long the content is (a
            // close-delimited response, or a transaction deserialized without the
            // field). Emptiness is not observable, so nothing is reported.
            None => None,
        }
    }

    fn description(&self) -> &'static str {
        "Reports a `200 (OK)` response that carries no content, so an operator can check whether `204 (No Content)` was meant instead. **Nothing is being violated.** RFC 9110 §15.3.1 says an origin server *\"ought to\"* send a 204 *\"if some aspect of the request indicates a preference for no content upon success\"* — a modal weaker than SHOULD, and a condition about the *request* that no field on the wire records, so this rule cannot tell the case the sentence is about from the case it is not. It reports both. The same section's preceding sentence expects a 200 to contain content *\"unless the message framing explicitly indicates that the content has zero length\"*, which is the very state reported here, and §6.4.1 says of every response that is not a HEAD response, a CONNECT tunnel, a 1xx, a 204 or a 304: *\"All other responses do include content, although that content might be of zero length.\"* A 200 returning an empty representation — an empty file, an empty collection — is therefore conforming, and reads as a finding only because the alternative status code is often the better answer. Two responses are exempt because they cannot carry content at all: responses to `HEAD` (§9.3.2) and 2xx responses to `CONNECT`, where the tunnel begins where the content would be and a 204 would not open it. Method tokens are compared case-sensitively (§9.1). Emptiness is read from the declared `Content-Length` when the response has no `Transfer-Encoding`, and otherwise from the captured content length; when neither is available the response is not reported, and an invalid `Content-Length` is left to `message_content_length`."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.1",
                note: "200 (OK) — the whole basis of this rule, and both of its sentences matter: a 200 is expected to contain content \"unless the message framing explicitly indicates that the content has zero length\" (the reported state is that exception, not a breach), and the 204 advice is an \"ought to\" conditioned on the request preferring no content, which is not observable. The same paragraph excludes CONNECT",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("15.3.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.5",
                note: "204 (No Content) — the alternative the advice names: success, no content, and terminated by the end of the header section",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("6.4.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-6.4.1",
                note: "Content Semantics — which responses have no content (HEAD, 2xx to CONNECT, 1xx, 204, 304) and, for every other response, that its content \"might be of zero length\": a zero-length 200 is contemplated by the specification",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("9.3.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.2",
                note: "HEAD — \"the server MUST NOT send content in the response\", so an empty response to HEAD says nothing about what the server intended",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("9.3.6"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6",
                note: "CONNECT — a 2xx switches the connection to tunnel mode immediately after the header section; 204 is not an alternative there",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("6.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3",
                note: "Message body length — a Transfer-Encoding overrides a Content-Length, so the declared length is read only in its absence; the captured content length is still consulted",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Type: application/json\nContent-Length: 24\n\n{\"status\":\"ok\",\"data\":1}",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(HEAD request)"),
                snippet: "HEAD /resource HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK\nDate: Mon, 01 Jan 2024 00:00:00 GMT\n",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(CONNECT tunnel — the content is where the tunnel starts)"),
                snippet: "CONNECT server.example.com:443 HTTP/1.1\nHost: server.example.com:443\n\nHTTP/1.1 200 OK\n\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Length: 0\n",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &Server200Vs204BodyConsistency;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_tx_with_response(
        status: u16,
        method: &str,
        headers: &[(&str, &str)],
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, headers);
        tx.request.method = method.into();
        tx
    }

    #[rstest]
    #[case(200, "POST", &[("content-length","0")], None, true)]
    #[case(200, "GET", &[("content-length","0")], None, true)]
    #[case(200, "GET", &[("content-length","0"),("transfer-encoding","chunked")], None, false)]
    #[case(200, "GET", &[("content-length","00")], None, true)]
    #[case(200, "GET", &[("content-length","10"), ("content-length","20")], None, false)]
    #[case(200, "GET", &[("content-length","abc")], None, false)]
    #[case(200, "HEAD", &[("content-length","0")], None, false)]
    #[case(200, "GET", &[("content-length","123")], None, false)]
    #[case(200, "GET", &[], None, false)]
    #[case(200, "GET", &[], Some(0), true)]
    #[case(200, "GET", &[], Some(10), false)]
    #[case(200, "GET", &[ ("transfer-encoding", "chunked") ], None, false)]
    #[case(204, "GET", &[ ("content-length", "0") ], None, false)]
    // Chunked framing declares no length, so the captured count is the only thing
    // that can show the content is empty -- and it used to be skipped along with
    // the `Content-Length` the Transfer-Encoding overrode.
    #[case(200, "GET", &[ ("transfer-encoding", "chunked") ], Some(0), true)]
    #[case(200, "GET", &[ ("transfer-encoding", "chunked") ], Some(10), false)]
    #[case(200, "GET", &[ ("content-length", "0"), ("transfer-encoding", "chunked") ], Some(10), false)]
    // A 2xx to CONNECT is a tunnel handshake: no content is the successful outcome,
    // and 204 would not open the tunnel.
    #[case(200, "CONNECT", &[], Some(0), false)]
    #[case(200, "CONNECT", &[("content-length", "0")], None, false)]
    // Neither exemption folds case: `head` and `connect` are not those methods.
    #[case(200, "head", &[("content-length", "0")], None, true)]
    #[case(200, "connect", &[], Some(0), true)]
    fn check_cases(
        #[case] status: u16,
        #[case] method: &str,
        #[case] headers: &[(&str, &str)],
        #[case] body_len: Option<u64>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = Server200Vs204BodyConsistency;
        let mut tx = make_tx_with_response(status, method, headers);
        // If the test case specifies a captured body length, apply it to the response
        // so the rule can observe it during checking.
        if let Some(len) = body_len {
            if let Some(resp) = tx.response.as_mut() {
                resp.body_length = Some(len);
            }
        }

        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for status {} method {} headers {:?} body_len {:?}",
                status,
                method,
                headers,
                body_len
            );
        } else {
            assert!(v.is_none(), "unexpected violation: {:?}", v);
        }
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "server_200_vs_204_body_consistency");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn no_response_returns_none() -> anyhow::Result<()> {
        let rule = Server200Vs204BodyConsistency;
        let tx = crate::test_helpers::make_test_transaction();
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn violation_message_for_content_length_zero() -> anyhow::Result<()> {
        let rule = Server200Vs204BodyConsistency;
        let tx = make_tx_with_response(200, "GET", &[("content-length", "0")]);
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .expect("expected violation");
        assert!(v.message.contains("Content-Length: 0"));
        Ok(())
    }

    #[test]
    fn violation_message_for_captured_zero() -> anyhow::Result<()> {
        let rule = Server200Vs204BodyConsistency;
        let mut tx = make_tx_with_response(200, "GET", &[]);
        // Simulate a captured decoded response body of length zero
        if let Some(resp) = tx.response.as_mut() {
            resp.body_length = Some(0);
        }
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .expect("expected violation");
        assert!(v.message.contains("captured length 0"));
        Ok(())
    }

    #[test]
    fn scope_is_server() {
        let rule = Server200Vs204BodyConsistency;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn id_is_rule_name() {
        let rule = Server200Vs204BodyConsistency;
        assert_eq!(rule.id(), "server_200_vs_204_body_consistency");
    }

    /// Builds a transaction out of a published snippet: an optional request
    /// message, then the response, whose content is whatever follows the blank
    /// line that ends its header section.
    fn tx_from_snippet(snippet: &str) -> crate::http_transaction::HttpTransaction {
        let mut lines = snippet.split('\n');
        let mut method = "GET".to_string();

        if !snippet.starts_with("HTTP/") {
            let request_line = lines.next().expect("a request line");
            method = request_line
                .split(' ')
                .next()
                .expect("a method token")
                .to_string();
            // Skip the request's field lines, up to the blank line between the
            // two messages.
            for line in lines.by_ref() {
                if line.is_empty() {
                    break;
                }
            }
        }

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
                body_length = Some(content.join("\n").len() as u64);
                break;
            }
            let (name, value) = line.split_once(": ").expect("a field line");
            headers.insert(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).expect("a field name"),
                hyper::header::HeaderValue::from_str(value).expect("a field value"),
            );
        }

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = method;
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
    /// `Compliant` snippet the rule reports is published as guidance. The
    /// CONNECT example is the one with teeth: before the exemption existed, the
    /// rule advised a tunnel handshake to become a 204.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() -> anyhow::Result<()> {
        use crate::rules::Compliance;
        let rule = Server200Vs204BodyConsistency;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let mut saw_a_finding = false;

        for ex in rule.examples() {
            let found = rule.check_transaction(
                &tx_from_snippet(ex.snippet),
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            );
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

    #[test]
    fn non_utf8_content_length_is_ignored() -> anyhow::Result<()> {
        // Create a response with a non-UTF8 Content-Length header and ensure
        // the rule does not report a violation (another rule handles malformed CL).
        let rule = Server200Vs204BodyConsistency;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        let bad_value = hyper::header::HeaderValue::from_bytes(&[0xFF])?;
        hm.insert(hyper::header::CONTENT_LENGTH, bad_value);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,
            body_length: None,
            trailers: None,
        });

        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
        Ok(())
    }
}
