// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageProblemDetailsStructure;

/// The JSON type of a parsed value, for a finding that has to say what the
/// content turned out to be instead of an object.
fn json_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

impl MessageProblemDetailsStructure {
    /// Every finding names the same contradiction — the declared media type
    /// against the content — and differs only in what the content turned out to
    /// be. `detail` is that clause, and it is what the tests key on.
    fn report(&self, severity: crate::lint::Severity, detail: &str) -> Violation {
        Violation {
            rule: self.id().into(),
            severity,
            message: format!(
                "Response declares 'application/problem+json' but {detail}; the content is not the problem details JSON object that media type identifies"
            ),
        }
    }
}

impl Rule for MessageProblemDetailsStructure {
    fn id(&self) -> &'static str {
        "message_problem_details_structure"
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

        // Two field lines: which media type the peer acts on is not knowable, so
        // there is no message here whose content can be measured against a
        // declared format. `message_content_type_well_formed` reports the
        // duplication itself.
        if resp.headers.get_all("content-type").iter().count() > 1 {
            return None;
        }

        let ct_str = crate::helpers::headers::get_header_str(&resp.headers, "content-type")?;
        let parsed = crate::helpers::headers::parse_media_type(ct_str).ok()?;
        let t = parsed.type_.to_ascii_lowercase();
        let sub = parsed.subtype.to_ascii_lowercase();
        // cite(RFC 9457 § 3): "When serialized in a JSON document, that format is identified with the "application/problem+json" media type."
        if t != "application" || sub != "problem+json" {
            return None;
        }

        // A content coding makes the octets on the wire the coded form, so they
        // are not a JSON document and were never meant to be. That disqualifies
        // reading them as one -- and nothing else: how many of them there are is
        // still evidence, and an empty content is empty either way.
        let coded = resp.headers.contains_key("content-encoding");

        // Skip byte inspection when the captured body is a truncated prefix
        // (streaming): a truncated JSON object would mis-parse. The length-based
        // checks below use the real `body_length`, so coverage degrades
        // gracefully. An untruncated capture with an empty prefix is an empty
        // body: the tee marks a capture truncated whenever the total exceeds the
        // prefix it kept.
        if let Some(b) = tx
            .response_body
            .as_ref()
            .filter(|_| !tx.response_body_over_limit)
        {
            if b.is_empty() {
                return Some(self.report(config.severity, "its content is empty"));
            }
            if coded {
                return None;
            }
            return match serde_json::from_slice::<serde_json::Value>(b) {
                Ok(serde_json::Value::Object(_)) => None,
                Ok(other) => Some(self.report(
                    config.severity,
                    &format!(
                        "its content is a JSON {}, not a JSON object",
                        json_kind(&other)
                    ),
                )),
                Err(_) => Some(self.report(config.severity, "its content is not a JSON document")),
            };
        }

        // No usable bytes. The capture's own octet count is the next evidence,
        // and it answers only the emptiness half of the question.
        if let Some(len) = resp.body_length {
            return (len == 0)
                .then(|| self.report(config.severity, "the capture counted zero content octets"));
        }

        // Nothing counted either -- a transaction deserialized from a capture
        // file carries no body bytes at all. What the sender declared is the
        // last evidence, and only when nothing overrides it.
        if !resp.headers.contains_key("transfer-encoding")
            && matches!(
                crate::helpers::headers::validate_content_length(&resp.headers),
                Ok(Some(0))
            )
        {
            return Some(self.report(config.severity, "it declares a Content-Length of zero"));
        }

        None
    }

    fn description(&self) -> &'static str {
        "When a server expresses an error using the Problem Details media type (`application/problem+json`), the response body SHOULD be a JSON object carrying problem details (see RFC 7807). This rule performs conservative, syntactic checks on such responses: it verifies the response is an error (4xx/5xx) and that `application/problem+json` responses include a non-empty body. Captured bodies are available to rules in memory; the `captures_include_body` setting only controls whether bodies are persisted to the captures file. When body bytes are present, the rule will attempt to parse the body and ensure it is a non-empty JSON object. If body bytes are not present, the rule conservatively flags when a captured or indicated Content-Length of zero is present."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "RFC 7807",
            section: Some("3.1"),
            url: "https://www.rfc-editor.org/rfc/rfc7807.html#section-3.1",
            note: "Problem Details for HTTP APIs",
        }]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 400 Bad Request\nContent-Type: application/problem+json\nContent-Length: 123\n\n{\"type\":\"about:blank\",\"title\":\"Bad Request\",\"detail\":\"invalid input\"}",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 500 Internal Server Error\nContent-Type: application/problem+json\nContent-Length: 0\n",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageProblemDetailsStructure;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// One constructor for every fixture, so no test is silent about an input
    /// the rule reads: the status, the field lines, the captured octets and the
    /// counted length are all named at each call site.
    fn fixture(
        status: u16,
        headers: &[(&str, &str)],
        body: Option<&'static [u8]>,
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
        tx.response_body = body.map(bytes::Bytes::from_static);
        tx
    }

    fn check(tx: &crate::http_transaction::HttpTransaction) -> Option<crate::lint::Violation> {
        let rule = MessageProblemDetailsStructure;
        rule.check_transaction(
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    const PJ: (&str, &str) = ("content-type", "application/problem+json");

    /// Every member of a problem details object is optional, so `{}` is a
    /// conforming one: it means "no semantics beyond the status code". §3.1
    /// introduces the members with "can have", §3.1.1 supplies "about:blank"
    /// when "type" is absent, and §4.2.1 closes it by saying that an object
    /// carrying no explicit "type" implicitly uses that URI.
    #[test]
    fn empty_object_is_a_conforming_problem_details_object() {
        let tx = fixture(500, &[PJ], Some(b"{}"), Some(2));
        assert!(check(&tx).is_none(), "{:?}", check(&tx));
    }

    /// The rule asks whether content labelled as problem details is problem
    /// details. That question does not depend on the status code, and RFC 9457
    /// says the format can be used with any of them.
    #[rstest]
    #[case(200)]
    #[case(204)]
    #[case(400)]
    #[case(500)]
    fn status_is_not_a_condition(#[case] status: u16) {
        let tx = fixture(status, &[PJ], Some(b"not json"), Some(8));
        let v = check(&tx).expect("expected a finding");
        assert!(v.message.contains("not a JSON document"), "{}", v.message);
    }

    #[rstest]
    #[case(b"[1,2]", "JSON array")]
    #[case(b"\"a\"", "JSON string")]
    #[case(b"42", "JSON number")]
    #[case(b"true", "JSON boolean")]
    #[case(b"null", "JSON null")]
    fn valid_json_that_is_not_an_object_is_reported(
        #[case] body: &'static [u8],
        #[case] clause: &str,
    ) {
        let tx = fixture(500, &[PJ], Some(body), Some(body.len() as u64));
        let v = check(&tx).expect("expected a finding");
        assert!(v.message.contains(clause), "{}", v.message);
    }

    #[test]
    fn a_problem_details_object_is_not_reported() {
        let tx = fixture(
            500,
            &[PJ],
            Some(b"{\"type\":\"about:blank\",\"title\":\"Internal Server Error\"}"),
            Some(52),
        );
        assert!(check(&tx).is_none(), "{:?}", check(&tx));
    }

    #[test]
    fn empty_captured_body_is_reported() {
        let tx = fixture(500, &[PJ], Some(b""), Some(0));
        let v = check(&tx).expect("expected a finding");
        assert!(v.message.contains("content is empty"), "{}", v.message);
    }

    /// A `Content-Encoding` makes the captured octets the coded form, so they
    /// cannot be parsed as JSON. The four bytes here are a gzip header.
    #[test]
    fn content_encoding_suppresses_the_json_parse() {
        let tx = fixture(
            500,
            &[PJ, ("content-encoding", "gzip")],
            Some(&[0x1f, 0x8b, 0x08, 0x00]),
            Some(4),
        );
        assert!(check(&tx).is_none(), "{:?}", check(&tx));
    }

    /// ...and nothing else. A coded representation of zero octets is still no
    /// representation at all.
    #[test]
    fn content_encoding_does_not_suppress_the_emptiness_finding() {
        let tx = fixture(500, &[PJ, ("content-encoding", "gzip")], Some(b""), Some(0));
        let v = check(&tx).expect("expected a finding");
        assert!(v.message.contains("content is empty"), "{}", v.message);
    }

    /// Two `Content-Type` field lines: the media type this message states is
    /// not the one the recipient is likely to act on, so there is nothing to
    /// measure the content against. Both orders, because reading the first
    /// value is what makes the order matter.
    #[rstest]
    #[case(&["application/problem+json", "text/html"])]
    #[case(&["text/html", "application/problem+json"])]
    fn duplicate_content_type_lines_are_declined(#[case] values: &[&str]) {
        let pairs: Vec<(&str, &str)> = values.iter().map(|v| ("content-type", *v)).collect();
        let tx = fixture(500, &pairs, Some(b"not json"), Some(8));
        assert!(check(&tx).is_none(), "{values:?}: {:?}", check(&tx));
    }

    /// The neighbour named at the decline reports that message, so the decline
    /// costs no coverage. Executed rather than assumed.
    #[test]
    fn the_owning_rule_reports_the_duplication_this_rule_declines() {
        let owner = crate::rules::message_content_type_well_formed::MessageContentTypeWellFormed;
        let tx = fixture(
            500,
            &[
                ("content-type", "application/problem+json"),
                ("content-type", "text/html"),
            ],
            Some(b"not json"),
            Some(8),
        );
        let v = owner.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[owner.id()]),
        );
        assert!(v.is_some(), "the owning rule said nothing");
    }

    /// A truncated prefix of a problem+json body would mis-parse; the rule must
    /// skip byte inspection and fall back to `body_length` (the real size).
    #[test]
    fn truncated_body_prefix_skips_byte_inspection() {
        let mut tx = fixture(500, &[PJ], Some(b"{\"type\":\"abo"), Some(4096));
        tx.response_body_over_limit = true;
        assert!(check(&tx).is_none(), "{:?}", check(&tx));
    }

    /// No captured bytes: the counted octets are the remaining evidence, and
    /// they answer only the emptiness half of the question.
    #[rstest]
    #[case(0, true)]
    #[case(10, false)]
    fn counted_length_cases(#[case] len: u64, #[case] expect_violation: bool) {
        let tx = fixture(500, &[PJ], None, Some(len));
        let v = check(&tx);
        assert_eq!(v.is_some(), expect_violation, "{v:?}");
        if let Some(v) = v {
            assert!(
                v.message.contains("counted zero content octets"),
                "{}",
                v.message
            );
        }
    }

    /// Nothing counted either — a transaction deserialized from a capture file
    /// carries no body bytes. What the sender declared is the last evidence.
    #[rstest]
    #[case(&[], false)]
    #[case(&[("content-length", "0")], true)]
    #[case(&[("content-length", " 0 ")], true)]
    #[case(&[("content-length", "10")], false)]
    #[case(&[("content-length", "0, 0")], true)]
    #[case(&[("content-length", "nonsense")], false)]
    // A declared length is the message's framing only when nothing overrides it.
    #[case(&[("content-length", "0"), ("transfer-encoding", "chunked")], false)]
    fn declared_length_cases(#[case] extra: &[(&str, &str)], #[case] expect_violation: bool) {
        let mut headers = vec![PJ];
        headers.extend_from_slice(extra);
        let tx = fixture(500, &headers, None, None);
        let v = check(&tx);
        assert_eq!(v.is_some(), expect_violation, "{extra:?}: {v:?}");
        if let Some(v) = v {
            assert!(
                v.message.contains("Content-Length of zero"),
                "{}",
                v.message
            );
        }
    }

    /// The media type is matched case-insensitively, and a parameter on it does
    /// not change which media type it is.
    #[rstest]
    #[case("application/problem+json", true)]
    #[case("APPLICATION/PROBLEM+JSON", true)]
    #[case("application/problem+json; charset=utf-8", true)]
    #[case("application/json", false)]
    #[case("application/problem+xml", false)]
    #[case("text/problem+json", false)]
    #[case("not-a-media-type", false)]
    fn media_type_gate(#[case] ct: &str, #[case] expect_violation: bool) {
        let tx = fixture(500, &[("content-type", ct)], Some(b"not json"), Some(8));
        assert_eq!(check(&tx).is_some(), expect_violation, "{ct}");
    }

    #[test]
    fn no_content_type_is_not_this_rules_finding() {
        let tx = fixture(500, &[], Some(b"not json"), Some(8));
        assert!(check(&tx).is_none());
    }

    #[test]
    fn scope_is_server() {
        assert_eq!(
            MessageProblemDetailsStructure.scope(),
            crate::rules::RuleScope::Server
        );
    }
}
