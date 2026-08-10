// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerStatusCodeValidRange;

impl Rule for ServerStatusCodeValidRange {
    fn id(&self) -> &'static str {
        "server_status_code_valid_range"
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

        let status = resp.status;
        // cite(RFC 9110 § 15): "The status code of a response is a three-digit integer code that describes the result of the request"
        if (100..=599).contains(&status) {
            return None;
        }

        // The message names which kind of out-of-range value this is, because the
        // three have different causes and only one of them can be written in a
        // status-line at all.
        let detail = match status {
            0..=99 => "A status-line cannot carry a value below 100 except as a leading-zero code such as `007` (RFC 9112 §4: `status-code = 3DIGIT`), which the HTTP/1.1 parser on the capture path rejects, so this value reached the linter from a capture record rather than from a parsed status-line.",
            600..=999 => "RFC 9110 §15 names 600..999 as the range implementations use for internal communication of non-HTTP status, such as library errors — one of those has reached the wire.",
            _ => "No `status-code` can express a value above 999 at all (RFC 9112 §4: `status-code = 3DIGIT`), so this value reached the linter from a capture record rather than from a parsed status-line.",
        };

        Some(Violation {
            rule: self.id().into(),
            severity: config.severity,
            message: format!(
                "Response status code {status} is outside the range 100-599; RFC 9110 §15 states that values outside it are invalid, and directs a client that receives one to process the response as if it had a 5xx (Server Error) status code. {detail}"
            ),
        })
    }

    fn description(&self) -> &'static str {
        "Reports a response whose status code falls outside the range RFC 9110 §15 defines — *\"All valid status codes are within the range of 100 to 599, inclusive\"* — and which the same section then calls invalid in as many words: *\"Values outside the range 100..599 are invalid.\"*\n\nNo sentence spells this as a MUST, and it does not need one: the RFC states the invalidity outright, and §16.2.2 closes the range against ever widening, because new status codes *\"are required to fall under one of the categories defined in Section 15\"* and those five categories are 1xx through 5xx. Either way the recipient gets nothing it can act on — §15 directs a client receiving an invalid status code to process the response as if it had a 5xx.\n\n**The three out-of-range cases have different causes, and the finding names which one it is.** A code in 600..999 is a three-digit value a status-line can carry, and §15 names that range as the one implementations use for internal, non-HTTP status such as library errors — so a finding there usually means an internal status leaked onto the wire. A value above 999 cannot be written as a `status-code` at all (RFC 9112 §4: `status-code = 3DIGIT`), and one below 100 only as a leading-zero code such as `007`, which HTTP/1.1 parsing on the capture path rejects; both of those reach the rule from a capture file supplied to the `lint` subcommand, where the status is read as a plain integer. That is also why only the first has a published example: the other two cannot be written as an HTTP message.\n\n**It does not check whether the code is registered, and an unregistered code in range is not a finding.** §15 requires a client to understand a status code's *class* and to treat an unrecognized code as equivalent to the x00 of that class — the RFC's own example is a 471 read as a 400 — so an in-range code nobody has registered is still well defined for every recipient. §15.1 asks only that additional codes *\"ought to be\"* registered, which is weaker than SHOULD, and the registry is open.\n\nThe reason-phrase beside the code is not read: RFC 9112 §4 makes it optional and asks clients to ignore it. What a *valid* status code implies for the rest of the message — which fields it may carry, whether it may have content, whether it is cacheable — belongs to the rules for each of those questions."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "RFC 9110",
            section: Some("15"),
            url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-15",
            note: "Status Codes: the three-digit code, the 100..599 range, and the statement that values outside it are invalid",
        }]
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
static REGISTRATION: &dyn crate::rules::Rule = &ServerStatusCodeValidRange;

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
        let rule = ServerStatusCodeValidRange;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status,
            version: "HTTP/1.1".into(),
            headers: hyper::HeaderMap::new(),

            body_length: None,
            trailers: None,
        });

        let config = crate::test_helpers::make_test_config_with_severity(
            "server_status_code_valid_range",
            "error",
        );

        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );

        if expect_violation {
            assert!(violation.is_some());
            let v = violation.unwrap();
            assert_eq!(v.rule, "server_status_code_valid_range");
            assert!(v.message.contains(&status.to_string()));
        } else {
            assert!(violation.is_none());
        }
    }

    /// The range is RFC 9110 § 15's and holds for every version, which is why this
    /// rule has no version gate — and why the two pseudo-header rules that used to
    /// make the same check no longer do. `message_http2_pseudo_headers_validity`
    /// made it on every transaction, HTTP/1.1 included; `message_http3_pseudo_headers_validity`
    /// made it behind an HTTP/3 gate. Both now decline, so these are the only
    /// reports left.
    #[rstest]
    #[case("HTTP/1.1")]
    #[case("HTTP/2")]
    #[case("HTTP/3")]
    fn out_of_range_is_reported_on_every_version(#[case] version: &str) {
        let rule = ServerStatusCodeValidRange;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(600, &[]);
        tx.request.version = version.into();
        tx.response.as_mut().expect("response").version = version.into();

        let violation = rule.check_transaction(
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
        let rule = ServerStatusCodeValidRange;
        let tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        let v = rule
            .check_transaction(
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
        let rule = ServerStatusCodeValidRange;

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
            let v = rule.check_transaction(
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
        let rule = ServerStatusCodeValidRange;
        let tx = crate::test_helpers::make_test_transaction();

        let config = crate::test_helpers::make_test_config_with_severity(
            "server_status_code_valid_range",
            "error",
        );

        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        );
        assert!(violation.is_none());
    }
}
