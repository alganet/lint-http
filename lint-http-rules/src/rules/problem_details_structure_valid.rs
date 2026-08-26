// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ProblemDetailsStructureValid;

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

impl ProblemDetailsStructureValid {
    /// Every finding names the same contradiction — the declared media type
    /// against the content — and differs only in what the content turned out to
    /// be. `detail` is that clause, and it is what the tests key on.
    ///
    /// The contradiction is between two things the message itself states, and
    /// what makes it one is definitional rather than a modal: the first sentence
    /// says the representation *is* in the format its metadata names, and the
    /// second says the recipient will process it as that format. No RFC writes a
    /// MUST that content match its `Content-Type`; §8.3 goes no further than
    /// calling the matching one the "correct" one and the alternative a
    /// misconfiguration. `description()` says so on the page an operator reads
    /// before enabling this rule.
    // cite(RFC 9110 § 8.1): "The representation data is in a format and encoding defined by the representation metadata header fields."
    // cite(RFC 9110 § 8.3): "The indicated media type defines both the data format and how that data is intended to be processed by a recipient, within the scope of the received message semantics, after any content codings indicated by Content-Encoding are decoded."
    // cite(RFC 9110 § 8.3): "In practice, resource owners do not always properly configure their origin server to provide the correct Content-Type for a given representation."
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

impl Rule for ProblemDetailsStructureValid {
    fn id(&self) -> &'static str {
        "problem_details_structure_valid"
    }

    // No sentence scopes this rule to responses. RFC 9457 describes problem
    // details only as content conveyed in a response and gives no meaning to a
    // request carrying the media type, so there is nothing here to measure such
    // a request against — but "the document never mentions it" is a claim about
    // silence, not a requirement, and it is recorded here rather than cited.
    // Note the status code is not part of this: §1 permits problem details on
    // any status, and the rule reports on all of them.
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

        // Two field lines: `get` below reads the first while the recipient is
        // likely to act on the last, so the format this message declares is not
        // the one in force, and there is nothing to measure the content against.
        // `content_type_valid` reports the duplication itself.
        // cite(RFC 9110 § 8.3): "Recipients often attempt to handle this error by using the last syntactically valid member of the list, leading to potential interoperability and security issues if different implementations have different error handling behaviors."
        if resp.headers.get_all("content-type").iter().count() > 1 {
            return None;
        }

        // With no `Content-Type` there is no declared format for the content to
        // contradict — the recipient is left to guess, which is a different
        // finding and `content_type_present`'s. A value that is not a
        // media type is `content_type_valid`'s.
        // cite(RFC 9110 § 8.3): "If a Content-Type header field is not present, the recipient MAY either assume a media type of "application/octet-stream" ([RFC2046], Section 4.5.1) or examine the data to determine its type."
        let ct_str = crate::helpers::headers::get_header_str(&resp.headers, "content-type")?;
        let parsed = crate::helpers::headers::parse_media_type(ct_str).ok()?;

        // Folded once, here, rather than at the comparison below.
        // cite(RFC 9110 § 8.3.1): "The type and subtype tokens are case-insensitive."
        let t = parsed.type_.to_ascii_lowercase();
        let sub = parsed.subtype.to_ascii_lowercase();

        // The JSON serialization only. RFC 9457 defines an equivalent XML one
        // and names its media type in an appendix; measuring an XML document
        // against that format needs an XML parser this crate does not have, so
        // `application/problem+xml` is excluded deliberately and `description()`
        // says so rather than leaving the omission to look like an oversight.
        // cite(RFC 9457 § 3): "When serialized in a JSON document, that format is identified with the "application/problem+json" media type."
        // cite(RFC 9457 § B): "The media type for this format is "application/problem+xml"."
        if t != "application" || sub != "problem+json" {
            return None;
        }

        // A content coding makes the octets on the wire the coded form, so they
        // are not a JSON document and were never meant to be. What that
        // disqualifies is reading them as one -- and nothing else: how many of
        // them there are is still evidence, and an empty content is empty
        // whatever was applied to it. A lone `identity` is not excepted: the
        // same section says it SHOULD NOT be sent, so the only message this
        // costs a finding is one already contradicting that sentence.
        // cite(RFC 9110 § 8.4): "The "Content-Encoding" header field indicates what content codings have been applied to the representation, beyond those inherent in the media type, and thus what decoding mechanisms have to be applied in order to obtain data in the media type referenced by the Content-Type header field."
        let coded = resp.headers.contains_key("content-encoding");

        // Skip byte inspection when the captured body is a truncated prefix
        // (streaming): a truncated JSON object would mis-parse. The bound is the
        // capture's, not the protocol's — no sentence licenses it — and the
        // length-based checks below use the real `body_length`, so coverage
        // degrades gracefully. An untruncated capture with an empty prefix is an
        // empty body: the tee marks a capture truncated whenever the total
        // exceeds the prefix it kept, so the two cannot be confused.
        if let Some(b) = tx
            .response_body
            .as_ref()
            .filter(|_| !tx.response_body_over_limit)
        {
            // Zero octets is not a JSON document. The sentence is about what a
            // JSON text is, and an empty octet sequence serializes no value.
            // cite(RFC 8259 § 2): "A JSON text is a serialized value."
            if b.is_empty() {
                return Some(self.report(config.severity, "its content is empty"));
            }
            if coded {
                return None;
            }
            return match serde_json::from_slice::<serde_json::Value>(b) {
                // An object of no members is a conforming problem details
                // object: every member is optional, and the one that carries the
                // format's meaning has a defined value for its own absence. So
                // `{}` says "no semantics beyond the status code", which is
                // what the registered `about:blank` type means.
                // cite(RFC 9457 § 3.1): "Problem detail objects can have the following members."
                // cite(RFC 9457 § 3.1.1): "When this member is not present, its value is assumed to be "about:blank"."
                // cite(RFC 9457 § 4.2.1): "Consequently, any problem details object not carrying an explicit "type" member implicitly uses this URI."
                Ok(serde_json::Value::Object(_)) => None,
                // Well-formed JSON, but not the structure the media type names.
                // cite(RFC 9457 § 3): "The canonical model for problem details is a JSON [JSON] object."
                Ok(other) => Some(self.report(
                    config.severity,
                    &format!(
                        "its content is a JSON {}, not a JSON object",
                        json_kind(&other)
                    ),
                )),
                // Not JSON at all. `from_slice` also refuses octets that are not
                // UTF-8, which is the second sentence: this is content the
                // recipient cannot decode, let alone parse.
                // cite(RFC 8259 § 2): "A JSON text is a serialized value."
                // cite(RFC 8259 § 8.1): "JSON text exchanged between systems that are not part of a closed ecosystem MUST be encoded using UTF-8"
                Err(_) => Some(self.report(config.severity, "its content is not a JSON document")),
            };
        }

        // No usable bytes. The capture's own octet count is the next evidence,
        // and it answers only the emptiness half of the question. The count is
        // of content: chunk sizes and the trailer section are not in it, so a
        // zero here is zero octets of representation.
        // cite(RFC 9110 § 6.4): "This abstract definition of content reflects the data after it has been extracted from the message framing."
        if let Some(len) = resp.body_length {
            return (len == 0)
                .then(|| self.report(config.severity, "the capture counted zero content octets"));
        }

        // Nothing counted either -- a transaction deserialized from a capture
        // file carries no body bytes at all, because they are not serialized.
        // What the sender declared is the last evidence, and it is the framing
        // only when nothing overrides it. The overriding sentence is HTTP/1.1's,
        // and so is the field it names; what holds wherever that field appears
        // is that the length beside it is not the length.
        // cite(RFC 9112 § 6.3): "If a message is received with both a Transfer-Encoding and a Content-Length header field, the Transfer-Encoding overrides the Content-Length."
        // cite(RFC 9112 § 6.3): "If a valid Content-Length header field is present without Transfer-Encoding, its decimal value defines the expected message body length in octets."
        // cite(RFC 9110 § 8.6): "The "Content-Length" header field indicates the associated representation's data length as a decimal non-negative integer number of octets."
        if !resp.headers.contains_key("transfer-encoding")
            && matches!(
                crate::helpers::headers::validate_content_length(&resp.headers),
                Ok(Some(0))
            )
        {
            return Some(self.report(config.severity, "it declares a Content-Length of zero"));
        }

        // A declared length above zero, an unreadable one, or none at all: the
        // content may be anything and nothing here has seen it.
        None
    }

    fn description(&self) -> &'static str {
        "Reports a response whose `Content-Type` is `application/problem+json` but whose content is not the problem details JSON object that media type identifies — content that is empty, that does not parse as JSON, or that parses as some other JSON value (an array, a string, a number). RFC 9457 defines the format; it obsoletes RFC 7807.\n\n**Any status code.** RFC 9457 says problem details \"can be used with any HTTP status code, but they most naturally fit the semantics of 4xx and 5xx responses\". Whether they *suit* a status is `problem_details_content_type`'s question; this rule's is whether content labelled as problem details is problem details, and that question reads the same on a 200 as on a 500.\n\n**An empty JSON object is conforming and is not reported.** Every member is optional: §3.1 introduces them with \"can have\", §3.1.1 says that when `type` is absent \"its value is assumed to be `about:blank`\", and §4.2.1 confirms that \"any problem details object not carrying an explicit `type` member implicitly uses this URI\" — the registered type meaning the problem has no semantics beyond the status code. So `{}` is a problem details object that says exactly that.\n\n**What the finding rests on.** No RFC states a MUST that content match its `Content-Type`. RFC 9110 §8.1 defines representation data as being \"in a format and encoding defined by the representation metadata header fields\", §8.3 says the indicated media type \"defines both the data format and how that data is intended to be processed by a recipient\", and the same section calls a server that does otherwise one that has not been configured \"to provide the correct Content-Type for a given representation\". A finding is a contradiction between two things the message itself states, not a matter of taste — but it is definitional in origin, not a stated requirement.\n\n**Limits.** Only the JSON serialization is checked: RFC 9457 defines an equivalent XML format (`application/problem+xml`) in Appendix B, and measuring an XML document against it needs a parser this crate does not have. A `Content-Encoding` means the captured octets are the coded form, so they are not parsed as JSON — the emptiness checks still apply, since a coded representation of nothing is still nothing. Two `Content-Type` field lines are declined: `Content-Type` is a singleton, recipients often act on the last member, and `content_type_valid` reports the duplication. A response carrying no `Content-Type` at all is `content_type_present`'s finding, and an unparseable one is `content_type_valid`'s.\n\nCaptured bodies are available to rules in memory; the `captures_include_body` setting only controls whether bodies are persisted to the captures file. A body captured as a truncated prefix is not parsed. Where no bytes are available — a transaction read back from a capture file — the emptiness half of the question is still answered from the counted octets, or failing that from a declared `Content-Length` of zero, which is evidence only when no `Transfer-Encoding` overrides it."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9457",
                section: Some("3"),
                url: "https://www.rfc-editor.org/rfc/rfc9457.html#section-3",
                note: "The problem details JSON object and the media type that identifies it; §3.1 and §3.1.1 are where every member is made optional and `type` is given a value for its own absence",
            },
            crate::rules::SpecRef {
                spec: "RFC 9457",
                section: Some("4.2.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9457.html#section-4.2.1",
                note: "`about:blank`, the registered problem type for a problem with no semantics beyond the status code — and the sentence saying an object carrying no explicit `type` implicitly uses it, which is why an empty object is conforming",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.1",
                note: "Representation data is in the format its metadata names — the sentence that makes a mismatch between the content and the `Content-Type` a contradiction rather than a preference; §8.3 adds what the recipient does with the indicated media type, and §8.4 that a content coding has to be undone first",
            },
            crate::rules::SpecRef {
                spec: "RFC 8259",
                section: Some("2"),
                url: "https://www.rfc-editor.org/rfc/rfc8259.html#section-2",
                note: "What a JSON text is — the measure for content that is empty or does not parse; §8.1 adds the UTF-8 requirement the parser also enforces",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("a problem details object"),
                snippet: "HTTP/1.1 403 Forbidden\nContent-Type: application/problem+json\nContent-Length: 70\n\n{\"type\":\"https://example.com/probs/out-of-credit\",\"title\":\"No credit\"}",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("no member is required — this one means \"about:blank\""),
                snippet: "HTTP/1.1 404 Not Found\nContent-Type: application/problem+json\nContent-Length: 2\n\n{}",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("the media type says JSON; the content is not a JSON document"),
                snippet: "HTTP/1.1 500 Internal Server Error\nContent-Type: application/problem+json\nContent-Length: 21\n\nInternal Server Error",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("well-formed JSON, but not the object the media type names"),
                snippet: "HTTP/1.1 422 Unprocessable Content\nContent-Type: application/problem+json\nContent-Length: 41\n\n[{\"detail\":\"must be a positive integer\"}]",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ProblemDetailsStructureValid;

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
        let rule = ProblemDetailsStructureValid;
        crate::test_helpers::run_rule(
            &rule,
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
    #[case(201)]
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
        let owner = crate::rules::content_type_valid::ContentTypeValid;
        let tx = fixture(
            500,
            &[
                ("content-type", "application/problem+json"),
                ("content-type", "text/html"),
            ],
            Some(b"not json"),
            Some(8),
        );
        let v = crate::test_helpers::run_rule(
            &owner,
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
            ProblemDetailsStructureValid.scope(),
            crate::rules::RuleScope::Server
        );
    }

    /// Each published snippet, judged by this rule, must reach the verdict its
    /// label carries — and at least one of them must actually produce the
    /// finding, so the guard cannot pass by never firing. The body after the
    /// blank line is fed as the captured content, because for this rule it *is*
    /// the input under test.
    #[test]
    fn published_examples_are_judged_by_this_rule() {
        use crate::rules::{Compliance, Rule as _};
        let rule = ProblemDetailsStructureValid;
        let mut saw_a_finding = false;

        for ex in rule.examples() {
            let (head, body) = ex.snippet.split_once("\n\n").unwrap_or((ex.snippet, ""));
            let mut lines = head.lines();
            let status = lines
                .next()
                .and_then(|line| line.strip_prefix("HTTP/1.1 "))
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|code| code.parse::<u16>().ok())
                .unwrap_or_else(|| {
                    panic!(
                        "the first line of an example is its status line: {:?}",
                        ex.snippet
                    )
                });
            let headers: Vec<(&str, &str)> = lines
                .map(|l| {
                    l.split_once(": ")
                        .unwrap_or_else(|| panic!("not a field line: {l:?}"))
                })
                .collect();

            // A published `Content-Length` is part of the message an operator
            // reads, so it has to agree with the octets beside it.
            if let Some((_, declared)) = headers.iter().find(|(n, _)| *n == "Content-Length") {
                assert_eq!(
                    declared.parse::<usize>().ok(),
                    Some(body.len()),
                    "declared length disagrees with the content: {:?}",
                    ex.snippet
                );
            }

            let mut tx = crate::test_helpers::make_test_transaction();
            tx.response = Some(crate::http_transaction::ResponseInfo {
                status,
                version: "HTTP/1.1".into(),
                headers: crate::test_helpers::make_headers_from_pairs(&headers),
                body_length: Some(body.len() as u64),
                trailers: None,
            });
            tx.response_body = Some(bytes::Bytes::copy_from_slice(body.as_bytes()));

            let v = check(&tx);
            match ex.compliance {
                Compliance::Compliant => assert!(v.is_none(), "{}: {v:?}", ex.snippet),
                Compliance::NonCompliant => {
                    assert!(v.is_some(), "{}", ex.snippet);
                    saw_a_finding = true;
                }
            }
        }
        assert!(saw_a_finding, "no published example produced a finding");
    }
}
