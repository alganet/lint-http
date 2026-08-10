// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// A PATCH request's content is a patch document, and RFC 5789 § 2 says a patch document
/// is identified by a media type. This rule reports a PATCH request that carries content
/// with no `Content-Type` naming that format — RFC 9110 § 8.3's SHOULD, read at the one
/// method whose content is processing instructions rather than a representation.
///
/// It does not judge the media type's *value*. No document defines a naming convention
/// for patch formats; RFC 5789's own examples use `application/example` and `text/example`,
/// and which formats a server accepts is discovered from `Accept-Patch`
/// (`client_patch_method_content_type_match`).
pub struct SemanticPatchPartialUpdate;

impl Rule for SemanticPatchPartialUpdate {
    fn id(&self) -> &'static str {
        "semantic_patch_partial_update"
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

        // The method token is case-sensitive, so the comparison is exact: a
        // request whose method is `patch` did not use PATCH, it used a method
        // with no defined semantics, and RFC 5789 § 2 is not a sentence about
        // it. `client_request_method_token_valid` is the rule that reports the
        // spelling.
        // cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
        // cite(RFC 5789 § 2): "The PATCH method requests that a set of changes described in the request entity be applied to the resource identified by the Request-URI."
        if tx.request.method != "PATCH" {
            return None;
        }

        // Whether the request carries content, on the evidence the capture
        // holds. A framing field is not the answer: `Transfer-Encoding` says how
        // the octets were delimited, not that there were any, and over HTTP/2
        // and HTTP/3 content arrives with no framing field at all. The shared
        // helper reads the captured count first and falls back to the sender's
        // declared length only where nothing was captured.
        let evidence =
            crate::helpers::headers::content_evidence(&tx.request.headers, tx.request.body_length)?;

        // Presence is the whole test, so `contains_key` answers it and no
        // decode is needed. A `Content-Type` whose octets are not visible ASCII
        // is a field that is *there*; what is wrong with it is
        // `message_content_type_well_formed`'s finding, not this rule's.
        if tx.request.headers.contains_key("content-type") {
            // The rule stops here. Whether the named media type is a patch
            // format is a question no sentence in RFC 5789 answers from the
            // request alone — there is no naming convention and no registry of
            // patch formats, and the document's own examples are
            // `application/example` and `text/example`. What a particular
            // server accepts is discovered from its `Accept-Patch`, which is
            // `client_patch_method_content_type_match`'s subject.
            return None;
        }

        // The requirement, and it is a SHOULD carrying an exception this rule
        // cannot evaluate.
        // cite(RFC 9110 § 8.3): "A sender that generates a message containing content SHOULD generate a Content-Type header field in that message unless the intended media type of the enclosed representation is unknown to the sender."
        Some(Violation {
            rule: self.id().into(),
            severity: config.severity,
            message: format!(
                "PATCH request carries content ({evidence}) with no Content-Type naming the patch document format"
            ),
        })
    }

    fn description(&self) -> &'static str {
        "Reports a `PATCH` request that carries content without a `Content-Type` naming the patch document format.\n\n**Why the field is load-bearing here.** A `PATCH` request's content is not a new representation of the resource — it is a set of instructions for changing one, and RFC 5789 §2 says that set \"is represented in a format called a *patch document* identified by a media type\". The media type is what tells the server which instructions it is holding, which is why §2 can require that \"[s]ervers MUST ensure that a received patch document is appropriate for the type of resource identified by the Request-URI\" and why §2.2 answers an unsupported one with `415 (Unsupported Media Type)`.\n\n**This is a SHOULD, and it has a stated exception.** The requirement is RFC 9110 §8.3's: a sender generating a message containing content \"SHOULD generate a Content-Type header field in that message *unless the intended media type of the enclosed representation is unknown to the sender*\". Nothing on the wire separates a sender that did not know from one that did not bother — but a client that built a patch document chose its format, so the exception is at its least plausible on this method. Without the field, §8.3 leaves the recipient two ways to proceed: assume `application/octet-stream`, or sniff the data.\n\n**The value is not judged.** A media type does not have to be *named* like a patch format to be one: RFC 5789's own examples are `application/example` and `text/example`, and §2 says outright that \"there is no single default patch document format that implementations are required to support\". There is no registry of patch formats and no naming convention, so nothing in a lone request says whether the type is one. What a particular server accepts is *discovered*, from the `Accept-Patch` it advertises (RFC 5789 §3.1) — `client_patch_method_content_type_match` is the rule that compares a request against it. This rule previously reported any media type whose type or subtype did not contain the string `patch`, which reported RFC 5789's own example.\n\n**Content, not framing.** The condition is that the message *contains content*, so the captured octet count decides it; a `Transfer-Encoding` is how octets were delimited, not evidence that there were any, and a chunked request whose only chunk is the terminator carries none. Only where nothing was captured does the rule fall back to the sender's declared `Content-Length`.\n\n**The method is compared exactly**, because RFC 9110 §9.1 says the method token is case-sensitive: a request whose method is `patch` is not a `PATCH` request, and `client_request_method_token_valid` is the rule that reports the spelling. A `Content-Type` whose octets are not visible ASCII counts as present here; `message_content_type_well_formed` reports what is wrong with it."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "RFC 5789",
            section: Some("2"),
            url: "https://www.rfc-editor.org/rfc/rfc5789.html#section-2",
            note: "Patch method semantics and patch document media types",
        }]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "PATCH /widgets/123 HTTP/1.1\nHost: example.com\nContent-Type: application/json-patch+json\nContent-Length: 48\n\n[ { \"op\": \"replace\", \"path\": \"/qty\", \"value\": 20 } ]",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— a patch format need not be *named* like one; this is RFC 5789 §2.1's own example"),
                snippet: "PATCH /file.txt HTTP/1.1\nHost: www.example.com\nContent-Type: application/example\nIf-Match: \"e0023aa4e\"\nContent-Length: 100\n\n[description of changes]",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— no content, so there is no patch document to identify"),
                snippet: "PATCH /widgets/123 HTTP/1.1\nHost: example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— content with no `Content-Type`, leaving the server to guess the patch format"),
                snippet: "PATCH /widgets/123 HTTP/1.1\nHost: example.com\nContent-Length: 5\n\nhello",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &SemanticPatchPartialUpdate;

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use rstest::rstest;

    fn make_tx_with_req(headers: Vec<(&str, &str)>) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "PATCH".to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&headers);
        tx
    }

    #[rstest]
    #[case(vec![("content-type", "application/json-patch+json"), ("content-length", "5")], false)]
    #[case(vec![("content-type", "application/merge-patch+json"), ("content-length", "1")], false)]
    // RFC 5789 §2.1's own example, and §2's "no single default patch document
    // format": a media type is not disqualified by not being spelled "patch".
    #[case(vec![("content-type", "application/example"), ("content-length", "100")], false)]
    #[case(vec![("content-type", "text/plain"), ("content-length", "3")], false)]
    #[case(vec![("content-type", "bad/type"), ("content-length", "1")], false)]
    #[case(vec![("content-length", "10")], true)]
    #[case(vec![], false)]
    // no content declared and none captured
    // A framing field is not content: a chunked request whose only chunk is the
    // terminator carries none, and this fixture declares no length either.
    #[case(vec![("transfer-encoding", "chunked")], false)]
    fn patch_content_type_cases(
        #[case] headers: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) {
        let rule = SemanticPatchPartialUpdate;
        let tx = make_tx_with_req(headers);
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for headers {:?}",
                tx.request.headers
            );
        } else {
            assert!(v.is_none(), "unexpected violation: {:?}", v);
        }
    }

    #[test]
    fn non_utf8_content_type_counts_as_present() {
        use hyper::header::HeaderValue;
        let rule = SemanticPatchPartialUpdate;
        let mut tx = make_tx_with_req(vec![("content-length", "1")]);
        // The field is on the wire; its octets are not visible ASCII.
        // `message_content_type_well_formed` owns what is wrong with it.
        tx.request.headers.append(
            "content-type",
            HeaderValue::from_bytes(b"text/plain\xFF").unwrap(),
        );
        tx.request.body_length = Some(1);
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "unexpected violation: {v:?}");
    }

    /// The HTTP/2 and HTTP/3 shape: content arrives with no framing field, and
    /// the captured octet count is the only evidence there is.
    #[test]
    fn captured_content_without_framing_fields_is_reported() {
        let rule = SemanticPatchPartialUpdate;
        let mut tx = make_tx_with_req(vec![]);
        tx.request.body_length = Some(5);
        tx.request_body = Some(Bytes::from("hello"));
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        let msg = v.expect("expected a violation").message;
        assert!(msg.contains("5 octets captured"), "message was: {msg}");
    }

    /// A captured count of zero outranks a `Content-Length` that claims
    /// otherwise: the octets are what the sentence is about, and the
    /// disagreement is `message_request_body_length_accuracy`'s finding.
    #[test]
    fn captured_zero_length_outranks_a_declared_length() {
        let rule = SemanticPatchPartialUpdate;
        let mut tx = make_tx_with_req(vec![("content-length", "5")]);
        tx.request.body_length = Some(0);
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "unexpected violation: {v:?}");
    }

    /// § 9.1: the method token is case-sensitive. A lowercase `patch` is a
    /// method with no defined semantics, so RFC 5789 § 2 does not measure it.
    #[test]
    fn lowercase_patch_is_not_patch() {
        let rule = SemanticPatchPartialUpdate;
        let mut tx = make_tx_with_req(vec![("content-length", "5")]);
        tx.request.method = "patch".into();
        tx.request.body_length = Some(5);
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "unexpected violation: {v:?}");
    }

    /// `Transfer-Encoding` says how the octets were delimited, not that there
    /// were any: a chunked request whose only chunk is the terminator carries
    /// no content, and § 8.3's SHOULD is about a message that contains some.
    #[test]
    fn chunked_request_with_no_content_is_not_reported() {
        let rule = SemanticPatchPartialUpdate;
        let mut tx = make_tx_with_req(vec![("transfer-encoding", "chunked")]);
        tx.request.body_length = Some(0);
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "unexpected violation: {v:?}");
    }

    /// Where nothing was captured, the sender's own declaration is what is
    /// left. This is the `lint` subcommand's shape: `request_body` is
    /// `#[serde(skip)]`, so a capture file carries neither the octets nor,
    /// where the proxy rejected an over-limit body, a length.
    #[test]
    fn declared_length_without_a_capture_is_reported() {
        let rule = SemanticPatchPartialUpdate;
        let tx = make_tx_with_req(vec![("content-length", "10")]);
        assert!(tx.request.body_length.is_none());
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        let msg = v.expect("expected a violation").message;
        assert!(msg.contains("Content-Length: 10"), "message was: {msg}");
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "semantic_patch_partial_update");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn validate_rules_with_invalid_config() {
        // missing severity should fail validation
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "semantic_patch_partial_update");
        // remove severity field from table
        if let Some(toml::Value::Table(ref mut table)) =
            cfg.rules.get_mut("semantic_patch_partial_update")
        {
            table.remove("severity");
        }

        let err = crate::rules::validate_rules(&cfg).expect_err("expected validation to fail");
        assert!(err.to_string().contains("Missing required 'severity'"));
    }
}
