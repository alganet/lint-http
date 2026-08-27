// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct HttpVersionSyntax;

impl Rule for HttpVersionSyntax {
    fn id(&self) -> &'static str {
        "http_version_syntax"
    }

    /// Both directions, and the request half is measured whether or not a
    /// response arrived. The sentence under this rule is addressed to whoever
    /// generated the protocol element, and a request whose version is
    /// unreadable was already unreadable when it was sent -- `Server` would
    /// have skipped every exchange whose upstream failed and every
    /// request-only lint.
    // cite(RFC 9110 § 2.2): "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
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
            // The request's version sits in the first line of the request message,
            // the response's in the first line of the response message. One
            // production, two start-lines, and the request is asked first because
            // it is the one a capture always holds.
            // cite(RFC 9112 § 3): "A request-line begins with a method token, followed by a single space (SP), the request-target, and another single space (SP), and ends with the protocol version."
            // cite(RFC 9112 § 4): "The first line of a response message is the status-line, consisting of the protocol version, a space (SP), the status code, and another space and ending with an OPTIONAL textual phrase describing the status code."
            let finding = judge("request", &tx.request.version).or_else(|| {
                let resp = tx.response.as_ref()?;
                judge("response", &resp.version)
            })?;

            Some(self.violation(ctx.severity, finding))
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "Reads the HTTP version a captured message arrived under and asks whether it is what `HTTP-version = HTTP-name \"/\" DIGIT \".\" DIGIT` generates: the four letters of `HTTP` in exactly that case, a `/`, one decimal digit, a `.`, and one decimal digit. RFC 9112 §2.3 states the case-sensitivity twice — once in the notation, where `%s` marks a case-sensitive string, and once in prose beside it — so `http/1.1` is not a spelling of `HTTP/1.1`. The requirement that a mismatch is a violation is RFC 9110 §2.2's, reached from an HTTP/1.1 production through §1.1, which puts this document's conformance criteria in the other one.\n\nThe finding names which of the production's three terminals failed, because they are three different mistakes: a name in the wrong case or absent, a version number that is not two digits around a period (`HTTP/1`, `HTTP/1.10`, `HTTP/11.0`), and the right shape holding a character that is not a digit (`HTTP/1.x`). It does **not** name the protocol version the message arrived under: the value that failed is the only thing that would have said, which is why a report of a malformed version can describe the value and nothing around it.\n\n**Only HTTP/1.x messages carry this as a field.** RFC 9112 §2.3 says the version of an HTTP/1.x message is indicated by an `HTTP-version` field in the start-line, and the other two versions say in so many words that they have nowhere to put one: RFC 9113 §8.3.1 and §8.3.2 give every HTTP/2 request and response an implicit protocol version of `2.0`, RFC 9114 §4.3.1 and §4.3.2 give every HTTP/3 request and response `3.0`. Both are written with the minor digit present, which is RFC 9110 §2.5's general rule — when a major version defines no minor versions, `0` is used wherever a minor version identifier is required. So the value is measured on every version: for one it is a transcription of what the message carried, and for the other two it is a number their own specifications state, written the way those specifications write it.\n\n**What this proxy records can never fail this rule.** The capture's version is rendered from an enumerated protocol version, so it is one of six strings — `HTTP/0.9`, `HTTP/1.0`, `HTTP/1.1`, `HTTP/2.0`, `HTTP/3.0`, and `HTTP/1.1` again for a version the HTTP library does not name — and every one of them derives from the production. A malformed version never reaches a capture either, because a request whose start-line does not parse is refused before there is a transaction to record. Every finding this rule can make is therefore about a capture written by some other tool and read back through `lint`, and that is the traffic it exists for.\n\nTwo things it does not check. RFC 9112 §2.3 requires an intermediary that is not a tunnel to send **its own** `HTTP-version` in forwarded messages; a capture records the message as received, not as forwarded, so nothing here can compare the two. And the relation between a request's version and the response's is left alone deliberately: §2.3 says a server **MAY** send an HTTP/1.0 response to an HTTP/1.1 request, and states no requirement for the pair to agree."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("2.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-2.3",
                note: "The production, the sentence saying it is case-sensitive, and the sentence saying only an HTTP/1.x message carries it in a start-line",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("2.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-2.5",
                note: "What the two digits mean, and the `0` used for a major version that defines no minor versions",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2",
                note: "The MUST NOT that makes a value matching no production a finding; RFC 9112 §1.1 is the bridge to it",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("3"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-3",
                note: "The request-line, which ends with the protocol version",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("4"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-4",
                note: "The status-line, which begins with it",
            },
            crate::rules::SpecRef {
                spec: "RFC 9113",
                section: Some("8.3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1",
                note: "HTTP/2 carries no version indicator; its implicit protocol version is `2.0`",
            },
            crate::rules::SpecRef {
                spec: "RFC 9114",
                section: Some("4.3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3.1",
                note: "HTTP/3 has nowhere to carry the identifier the request line holds; its implicit protocol version is `3.0`",
            },
            crate::rules::SpecRef {
                spec: "RFC 5234",
                section: Some("B.1"),
                url: "https://www.rfc-editor.org/rfc/rfc5234.html#appendix-B.1",
                note: "`DIGIT = %x30-39` — the alphabet the two positions admit",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("Both start-lines carry the production: the name in uppercase, one digit either side of the period."),
                snippet: "GET /path HTTP/1.1\nHost: example\n\nHTTP/1.1 200 OK\nContent-Type: text/plain\n\nHello",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("A version with no minor versions of its own is written with the `0` RFC 9110 §2.5 supplies, which is how RFC 9114 §4.3.1 states it. Neither line is on the wire — HTTP/3 has no start-line — but a capture records the version anyway, and this is the spelling."),
                snippet: "GET /path HTTP/3.0\nHost: example\n\nHTTP/3.0 200 OK\nContent-Type: text/plain\n\nHello",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("The name is a case-sensitive string, so `http` is not the name; and `1.10` is two digits in the minor position where the production writes one."),
                snippet: "GET /path http/1.1\nHost: example\n\nHTTP/1.10 200 OK\nContent-Type: text/plain\n\nHello",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("The right shape, the wrong alphabet: `x` is not a `DIGIT`. The request is reported first because a capture always holds one."),
                snippet: "GET /path HTTP/1.x\nHost: example\n\nHTTP/1.1 200 OK\nContent-Type: text/plain\n\nHello",
            },
        ]
    }
}

/// Measure one message's version against the production, and say what failed.
///
/// The message names the direction and not the start-line the value came from.
/// Over HTTP/1.x it is a field in a request-line or a status-line; over the
/// other two versions there is no start-line to have read it from -- and which
/// of the three this message is would have been said by the very value that
/// failed to parse, so there is nothing here to name it with.
// cite(RFC 9112 § 2.3): "The version of an HTTP/1.x message is indicated by an HTTP-version field in the start-line."
// cite(RFC 9113 § 8.3.1): "Individual HTTP/2 requests do not carry an explicit indicator of protocol version."
// cite(RFC 9114 § 4.3.1): "HTTP/3 does not define a way to carry the version identifier that is included in the HTTP/1.1 request line."
fn judge(direction: &str, value: &str) -> Option<String> {
    // The production lives in `http_version`, which owns its transcription
    // and the per-terminal reason; what belongs here is why failing it is a
    // violation. RFC 9112 states no modal about the syntax of its own grammar,
    // so the MUST NOT comes from the other document and § 1.1 is the bridge.
    // cite(RFC 9110 § 2.2): "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules."
    // cite(RFC 9112 § 1.1): "Conformance criteria and considerations regarding error handling are defined in Section 2 of [HTTP]."
    let why = crate::http_version::parse(value).err()?;

    // The value is escaped into the message for the same reason a field value
    // is: a capture read back from another tool can hold octets that would
    // corrupt the finding rather than appear in it.
    let shown = crate::helpers::headers::shown_in_finding(value);
    Some(format!(
        "The {direction}'s HTTP version, '{shown}', is not an HTTP-version -- {why}. \
         The production is the name 'HTTP', a '/', a decimal digit, a '.', and a decimal \
         digit: the first digit names the messaging syntax that carried this message and \
         the second is what its sender is conformant with. A sender must not generate a \
         protocol element that does not match the grammar, and this value matches none, so \
         nothing here can say which version of HTTP this message arrived under -- the value \
         that failed is what would have said."
    ))
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &HttpVersionSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn judge_tx(request: &str, response: Option<&str>) -> Option<String> {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = request.into();
        tx.response = response.map(|v| crate::http_transaction::ResponseInfo {
            status: 200,
            version: v.into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[]),
            body_length: None,
            trailers: None,
        });
        let rule = HttpVersionSyntax;
        crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .map(|v| v.message)
    }

    /// Every string this proxy can record. `format_http_version` in
    /// `lint-http-proxy/src/proxy/hop_by_hop.rs` is a total function over an
    /// enumerated protocol version, and each of its arms names a pair of digits
    /// rendered by `HttpVersion`'s `Display` -- so the conformance is now
    /// structural rather than a promise, and `HTTP/1.1` appears twice because a
    /// version the HTTP library does not name falls through to it. These cases
    /// pin the claim `description()` makes to an operator: a finding from this
    /// rule is about a capture some other tool wrote.
    #[rstest]
    #[case("HTTP/0.9")]
    #[case("HTTP/1.0")]
    #[case("HTTP/1.1")]
    #[case("HTTP/2.0")]
    #[case("HTTP/3.0")]
    fn nothing_this_proxy_records_is_reported(#[case] version: &str) {
        assert_eq!(judge_tx(version, Some(version)), None);
    }

    /// The version this proxy wrote for HTTP/3 until 2026-08-03 was `HTTP/3`,
    /// and this rule accepted it under a comment calling it "a valid internal
    /// form" -- an exemption resting on no sentence, against RFC 9114 § 4.3.1's
    /// `3.0` and RFC 9110 § 2.5's rule for supplying the minor digit. A capture
    /// from another tool can still hold it, and it is a finding.
    #[test]
    fn a_version_number_with_no_minor_digit_is_reported() {
        let msg = judge_tx("HTTP/3", None).expect("must be reported");
        assert!(msg.contains("'HTTP/3'"), "{msg}");
        assert!(msg.contains("single digit"), "{msg}");
    }

    /// The three terminals of the production are three findings, and the
    /// message says which one failed.
    #[rstest]
    #[case("http/1.1", "exactly that case")]
    #[case("HTTP/1.1", "")]
    #[case("1.1", "exactly that case")]
    #[case("", "exactly that case")]
    #[case("HTTP/1", "single digit")]
    #[case("HTTP/1.", "single digit")]
    #[case("HTTP/11.0", "single digit")]
    #[case("HTTP/1.10", "single digit")]
    #[case("HTTP/1.1.1", "single digit")]
    #[case("HTTP/1.x", "decimal digit")]
    fn the_request_names_the_terminal_that_failed(#[case] version: &str, #[case] reason: &str) {
        let got = judge_tx(version, None);
        if reason.is_empty() {
            assert_eq!(got, None);
            return;
        }
        let msg = got.expect("must be reported");
        assert!(msg.starts_with("The request's HTTP version, "), "{msg}");
        assert!(msg.contains(reason), "{msg}");
    }

    /// The response half is measured with the same production and names itself.
    #[test]
    fn the_response_is_measured_too() {
        let msg = judge_tx("HTTP/1.1", Some("HTTP/1.1.1")).expect("must be reported");
        assert!(msg.starts_with("The response's HTTP version, "), "{msg}");
    }

    /// The request is asked first: a capture always holds one, and a response
    /// may be absent entirely.
    #[test]
    fn the_request_is_reported_before_the_response() {
        let msg = judge_tx("http/1.1", Some("HTTP/1.1.1")).expect("must be reported");
        assert!(msg.starts_with("The request's HTTP version, "), "{msg}");
    }

    /// A transaction whose upstream never answered still has its request
    /// measured. `RuleScope::Server` would have skipped it.
    #[test]
    fn a_request_with_no_response_is_still_measured() {
        assert!(judge_tx("HTTP/1.x", None).is_some());
        assert_eq!(HttpVersionSyntax.scope(), crate::rules::RuleScope::Both);
    }

    /// The finding says nothing about which version of HTTP the message arrived
    /// under, because the value that failed is the only thing that would have
    /// said. Naming a start-line only one of the three versions has is the
    /// mistake this guards.
    #[test]
    fn the_finding_names_no_version_and_no_start_line() {
        let msg = judge_tx("HTTP/9.9.9", None).expect("must be reported");
        for absent in ["HTTP/1.x", "request-line", "status-line", "pseudo-header"] {
            assert!(!msg.contains(absent), "{absent} in {msg}");
        }
    }

    /// A capture from another tool can hold octets that would corrupt the
    /// finding rather than appear in it; the value is escaped the way a field
    /// value is.
    #[test]
    fn an_unprintable_octet_is_escaped_into_the_message() {
        let msg = judge_tx("HTTP/1.1\t", None).expect("must be reported");
        assert!(msg.contains("\\t"), "{msg}");
        assert!(!msg.contains('\t'), "{msg}");
    }
}
