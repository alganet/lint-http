// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct StatusCodeValidRange;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_15: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15",
    note: "Status Codes: the three-digit code, the 100..599 range, the statement that values outside it are invalid, what 600..999 is used for, and what a client does with an invalid code",
};
const RFC_9110_15_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("15.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.1",
    note: "Overview of Status Codes: additional codes `ought to be` registered — the modal that keeps this rule from checking registration",
};
const RFC_9110_16_2_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("16.2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-16.2.2",
    note: "Considerations for New Status Codes: a new code must fall under one of the five classes §15 defines, so the range cannot widen",
};
const RFC_9112_4: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9112",
    section: Some("4"),
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-4",
    note: "Status Line: `status-code = 3DIGIT`, the written form an HTTP/1.1 response can carry, and the optional reason phrase this rule does not read",
};
const RFC_9110_2_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("2.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2",
    note: "Conformance: a sender must not generate an element that does not match its ABNF — reached from RFC 9112 §1.1, and the modal behind the one value no `status-code` can express",
};

impl Rule for StatusCodeValidRange {
    fn id(&self) -> &'static str {
        "status_code_valid_range"
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
            // A status code is something a *response* has. `RuleScope::Server` above is
            // the engine's dispatch filter and not a sentence; this is the sentence, and
            // it is the definition the range check below used to be hung on.
            //
            // The code and nothing beside it: the reason phrase is not retained by the
            // canonical transaction model, and there would be little to measure it
            // against if it were — RFC 9112 § 4 makes it optional and asks the client to
            // disregard what it says.
            //
            // cite(RFC 9110 § 15): "The status code of a response is a three-digit integer code that describes the result of the request and the semantics of the response, including whether the request was successful and what content is enclosed (if any)."
            // cite(RFC 9112 § 4): "A client SHOULD ignore the reason-phrase content because it is not a reliable channel for information"
            let Some(resp) = &tx.response else {
                return None;
            };

            let status = resp.status;

            // The range, and the sentence that makes a value outside it a finding rather
            // than an observation. Worth stating which it is, because three rules in this
            // family have just had a claim shrunk to advice on finding that the rule's own
            // section merely *defines* its subject (§ 10.2.3's `Retry-After`, § 10.2.2's
            // placement rule). This is the other answer: "Values outside the range
            // 100..599 are invalid" is not a definition of a status code, it is a verdict
            // on a set of them. § 2.2's ABNF MUST NOT is not what carries it either —
            // `3DIGIT` admits 600 quite happily — and it appears below only on the one arm
            // where the value cannot be written at all.
            //
            // § 16.2.2 is the same sentence aimed at the future: no registration can widen
            // the range, because a new code must fall into one of § 15's five classes.
            //
            // cite(RFC 9110 § 15): "All valid status codes are within the range of 100 to 599, inclusive."
            // cite(RFC 9110 § 15): "Values outside the range 100..599 are invalid."
            // cite(RFC 9110 § 16.2.2): "New status codes are required to fall under one of the categories defined in Section 15."
            if (100..=599).contains(&status) {
                // An in-range code nobody has registered is still well defined: every
                // recipient is required to read it as the x00 of its class, and § 15.1
                // asks only that additional codes "ought to be" registered — weaker than
                // SHOULD, over an open registry. So there is no allowlist of known codes
                // here, and § 15's own example, a 471, is not a finding.
                //
                // cite(RFC 9110 § 15): "However, a client MUST understand the class of any status code, as indicated by the first digit, and treat an unrecognized status code as being equivalent to the x00 status code of that class."
                // cite(RFC 9110 § 15.1): "All such status codes ought to be registered within the "Hypertext Transfer Protocol (HTTP) Status Code Registry", as described in Section 16.2."
                return None;
            }

            // What the recipient does with it, which is the same for all three arms and is
            // the part an operator needs: the status is not read and rejected, it is
            // replaced, so whatever the sender meant by it arrives as a server error.
            //
            // The written form bounds two of the three arms, so the grammar sits above
            // them: three digits, no more and no fewer.
            //
            // cite(RFC 9110 § 15): "A client that receives a response with an invalid status code SHOULD process the response as if it had a 5xx (Server Error) status code."
            // cite(RFC 9112 § 4): "status-code    = 3DIGIT"
            let detail = match status {
                // Below 100. `3DIGIT` would admit `007`, so the grammar is not what stops
                // this one and the message does not claim it is; the status parser on the
                // capture path is, which a test below executes rather than assumes. That
                // holds for every version — an HTTP/2 or HTTP/3 `:status` is parsed into
                // the same `hyper::StatusCode`.
                0..=99 => "A status-line cannot carry a value below 100 except as a leading-zero code such as `007` (RFC 9112 §4: `status-code = 3DIGIT`), which the status parser on the capture path rejects for every version, so this value reached the linter from a capture record rather than from a parsed message.",
                // 600..999: three digits, writable, and § 15 names what is usually being
                // written — an internal library status that escaped onto the wire.
                //
                // cite(RFC 9110 § 15): "Implementations often use three-digit integer values outside of that range (i.e., 600..999) for internal communication of non-HTTP status (e.g., library errors)."
                600..=999 => "RFC 9110 §15 names 600..999 as the range implementations use for internal communication of non-HTTP status, such as library errors — one of those has reached the wire.",
                // Above 999: the one arm no status-line can express, and so the one arm
                // where § 2.2's MUST NOT applies. It reaches RFC 9112's grammar through
                // § 1.1, which hands that document's conformance criteria to RFC 9110 § 2
                // — the bridge is worth citing, because the modal lives in the other
                // document from the production it governs.
                //
                // cite(RFC 9112 § 4): "The status-code element is a 3-digit integer code describing the result of the server's attempt to understand and satisfy the client's corresponding request."
                // cite(RFC 9112 § 1.1): "Conformance criteria and considerations regarding error handling are defined in Section 2 of [HTTP]."
                // cite(RFC 9110 § 2.2): "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules."
                _ => "No `status-code` can express a value above 999 at all (RFC 9112 §4: `status-code = 3DIGIT`), so this value reached the linter from a capture record rather than from a parsed status-line.",
            };

            Some(self.violation(ctx.severity, format!(
                    "Response status code {status} is outside the range 100-599; RFC 9110 §15 states that values outside it are invalid, and directs a client that receives one to process the response as if it had a 5xx (Server Error) status code. {detail}"
                )))
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "Reports a response whose status code falls outside the range RFC 9110 §15 defines — *\"All valid status codes are within the range of 100 to 599, inclusive\"* — and which the same section then calls invalid in as many words: *\"Values outside the range 100..599 are invalid.\"*\n\nNo sentence spells this as a MUST, and it does not need one: the RFC states the invalidity outright, and §16.2.2 closes the range against ever widening, because new status codes *\"are required to fall under one of the categories defined in Section 15\"* and those five categories are 1xx through 5xx. Either way the recipient gets nothing it can act on — §15 directs a client receiving an invalid status code to process the response as if it had a 5xx.\n\n**The three out-of-range cases have different causes, and the finding names which one it is.** A code in 600..999 is a three-digit value a status-line can carry, and §15 names that range as the one implementations use for internal, non-HTTP status such as library errors — so a finding there usually means an internal status leaked onto the wire. A value above 999 cannot be written as a `status-code` at all (RFC 9112 §4: `status-code = 3DIGIT`), and one below 100 only as a leading-zero code such as `007`, which the status parser on the capture path rejects for every version; both of those reach the rule from a capture file supplied to the `lint` subcommand, where the status is read as a plain integer. That is also why only the first has a published example: an example is a message, and no message this toolchain can parse carries the other two.\n\n**It does not check whether the code is registered, and an unregistered code in range is not a finding.** §15 requires a client to understand a status code's *class* and to treat an unrecognized code as equivalent to the x00 of that class — the RFC's own example is a 471 read as a 400 — so an in-range code nobody has registered is still well defined for every recipient. §15.1 asks only that additional codes *\"ought to be\"* registered, which is weaker than SHOULD, and the registry is open.\n\nThe reason-phrase beside the code is not read: RFC 9112 §4 makes it optional and asks clients to ignore it. What a *valid* status code implies for the rest of the message — which fields it may carry, whether it may have content, whether it is cacheable — belongs to the rules for each of those questions."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_15,
            RFC_9110_15_1,
            RFC_9110_16_2_2,
            RFC_9112_4,
            RFC_9110_2_2,
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("Response"),
                snippet: "HTTP/1.1 200 OK",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("Response (unregistered code, in range)"),
                snippet: "HTTP/1.1 471 Unrecognized",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Response (internal non-HTTP status on the wire)"),
                snippet: "HTTP/1.1 600 Internal Library Error",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &StatusCodeValidRange;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(200, false)]
    #[case(100, false)]
    #[case(599, false)]
    // Unregistered, in range: §15 makes it the x00 of its class to every
    // recipient, so it is not this rule's finding.
    #[case(471, false)]
    #[case(99, true)]
    #[case(600, true)]
    #[case(999, true)]
    #[case(0, true)]
    #[case(1000, true)]
    #[case(u16::MAX, true)]
    fn check_status_range(#[case] status: u16, #[case] expect_violation: bool) {
        let rule = StatusCodeValidRange;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: hyper::HeaderMap::new(),

            body_length: None,
            trailers: None,
        });

        let config =
            crate::test_helpers::make_test_config_with_severity("status_code_valid_range", "error");

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );

        if expect_violation {
            assert!(violation.is_some());
            let v = violation.unwrap();
            assert_eq!(v.rule, "status_code_valid_range");
            assert!(v.message.contains(&status.to_string()));
        } else {
            assert!(violation.is_none());
        }
    }

    /// The range is RFC 9110 § 15's and holds for every version, which is why this
    /// rule has no version gate — and why the two pseudo-header rules that used to
    /// make the same check no longer do. `http2_pseudo_headers_valid`
    /// made it on every transaction, HTTP/1.1 included; `http3_pseudo_headers_valid`
    /// made it behind an HTTP/3 gate. Both now decline, so these are the only
    /// reports left.
    #[rstest]
    #[case("HTTP/1.1")]
    #[case("HTTP/2.0")]
    #[case("HTTP/3.0")]
    fn out_of_range_is_reported_on_every_version(#[case] version: &str) {
        let rule = StatusCodeValidRange;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(600, &[]);
        tx.request.version = version.into();
        tx.response.as_mut().expect("response").version = version.into();

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(violation.is_some(), "{version}");
    }

    /// The message is derived data: it names the status, states what the RFC says
    /// about the range rather than a section number nothing verifies, and says
    /// which of the three out-of-range cases this one is.
    #[rstest]
    #[case(600, "internal communication of non-HTTP status")]
    #[case(999, "internal communication of non-HTTP status")]
    #[case(99, "leading-zero code")]
    #[case(0, "leading-zero code")]
    #[case(1000, "above 999")]
    fn the_message_names_the_case(#[case] status: u16, #[case] expected: &str) {
        let rule = StatusCodeValidRange;
        let tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .expect("expected violation");

        assert!(v.message.contains(&status.to_string()), "{}", v.message);
        assert!(
            v.message.contains("outside the range 100-599"),
            "{}",
            v.message
        );
        assert!(v.message.contains("as if it had a 5xx"), "{}", v.message);
        assert!(v.message.contains(expected), "{}", v.message);
    }

    /// The reachability claim the description and the sub-100 message rest on,
    /// executed rather than assumed: the status on the proxy path is
    /// `hyper::StatusCode::as_u16()`, and that parser admits three digits in
    /// 100..=999 and rejects a leading-zero code. So a status below 100 or above
    /// 999 can only have arrived in a capture file, where `ResponseInfo.status`
    /// is deserialized as a plain `u16`.
    #[test]
    fn the_wire_parser_admits_only_100_to_999() {
        use hyper::StatusCode;
        assert!(StatusCode::from_u16(99).is_err());
        assert!(StatusCode::from_u16(100).is_ok());
        assert!(StatusCode::from_u16(600).is_ok());
        assert!(StatusCode::from_u16(999).is_ok());
        assert!(StatusCode::from_u16(1000).is_err());
        assert!(StatusCode::from_bytes(b"099").is_err());
        assert!(StatusCode::from_bytes(b"600").is_ok());

        let json = r#"{"status":1000,"version":"HTTP/1.1","headers":[],"body_length":null}"#;
        let resp: crate::http_transaction::ResponseInfo =
            serde_json::from_str(json).expect("a capture record carries the status as an integer");
        assert_eq!(resp.status, 1000);
    }

    /// Every published snippet is run through the rule.
    #[test]
    fn published_examples_are_judged_by_this_rule() {
        use crate::rules::{Compliance, Rule as _};
        let rule = StatusCodeValidRange;

        for ex in rule.examples() {
            let status = ex
                .snippet
                .lines()
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

            let tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
            let v = crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            );
            match ex.compliance {
                Compliance::Compliant => assert!(v.is_none(), "{}: {v:?}", ex.snippet),
                Compliance::NonCompliant => assert!(v.is_some(), "{}", ex.snippet),
            }
        }
    }

    #[test]
    fn check_missing_response() {
        let rule = StatusCodeValidRange;
        let tx = crate::test_helpers::make_test_transaction();

        let config =
            crate::test_helpers::make_test_config_with_severity("status_code_valid_range", "error");

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(violation.is_none());
    }
}
