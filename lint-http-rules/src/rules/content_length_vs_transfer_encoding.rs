// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::content_length::{CONTENT_LENGTH_FORBIDDEN, RFC_9112_6_2};
use crate::violations::ViolationDef;

/// One defect, and it is the `Content-Length`'s: § 6.2 forbids sending that
/// field in a transfer-coded message, so the field that may not be there is the
/// one the id names. The direction is not part of it — a request and a response
/// that each frame themselves twice are the same defect.
static DECLARED: &[&ViolationDef] = &[&CONTENT_LENGTH_FORBIDDEN];

pub struct ContentLengthVsTransferEncoding;

/// The reference this rule owns beyond the catalogue's § 6.2: the recipient
/// side, which is why the pairing is worth reporting rather than tidying.
const RFC_9112_6_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9112",
    section: Some("6.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3",
    note: "The recipient side and the stakes: Transfer-Encoding overrides, a forwarding intermediary must strip the Content-Length, and such a message may be an attempt at request smuggling or response splitting",
};

impl RuleMeta for ContentLengthVsTransferEncoding {
    fn id(&self) -> &'static str {
        "content_length_vs_transfer_encoding"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Content-Length vs Transfer-Encoding")
    }

    fn description(&self) -> &'static str {
        "This rule flags messages (requests or responses) that include both `Content-Length` and `Transfer-Encoding` headers. A sender must never combine them: the two describe message framing differently, so a message carrying both says two things about where it ends.\n\nRecipients are told to let `Transfer-Encoding` win and an intermediary that forwards the message must strip the `Content-Length` first. Where that does not happen consistently, two recipients can disagree about the message boundary — the primitive behind request smuggling and response splitting — so the combination is treated as an attack signal rather than mere redundancy."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9112_6_2, RFC_9112_6_3]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// **One defect, asked of each half separately.** A message that frames its
    /// content twice is ambiguous to its recipient, and the sender that framed
    /// it is the one answerable — the client for the request, the origin for the
    /// response.
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::PerSite
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("Message"),
                snippet: "POST /submit HTTP/1.1\nHost: example.com\nContent-Length: 15\n\npayload",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Message"),
                snippet: "POST /submit HTTP/1.1\nHost: example.com\nContent-Length: 15\nTransfer-Encoding: chunked",
            },
        ]
    }
}

impl Rule for ContentLengthVsTransferEncoding {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // One finding per section, and neither answers for the other. "In any
        // message" is what puts both directions in scope, and a request framing
        // itself twice and a response framing itself twice are two messages, two
        // senders and two repairs — so a client sending the pair no longer
        // stands in for the origin that sent it back. Both report the one id,
        // because the defect is the same one written at opposite ends of the
        // exchange; the prohibition is quoted on `content_length_forbidden`.
        //
        // **A smuggling probe is exactly the transaction where both halves
        // carry it.** A client that frames a request twice to find out how a
        // chain resolves it is answered by an origin whose own response frames
        // itself twice, and the second half was the silent one — `--about
        // server` said nothing at all about a message the entry calls an attack
        // primitive.
        let section = |headers: &hyper::HeaderMap, side: &str| -> Option<String> {
            //
            // The recipient side is why this is worth more than a style note. The two
            // fields give conflicting framing, recipients are told to resolve the
            // conflict one way, and disagreement between two recipients about where a
            // message ends is exactly the primitive that request smuggling and response
            // splitting are built on — so the pairing is treated as an attack signal,
            // not merely as redundancy.
            // cite(RFC 9112 § 6.3): "If a message is received with both a Transfer-Encoding and a Content-Length header field, the Transfer-Encoding overrides the Content-Length."
            // cite(RFC 9112 § 6.3): "An intermediary that chooses to forward the message MUST first remove the received Content-Length field and process the Transfer-Encoding"
            // The section is named and both values are shown. With the two
            // halves reported separately the entry's own static sentence would
            // be one sentence printed twice, differing in nothing an operator
            // reads — and the values are what says which line to delete.
            if !headers.contains_key("content-length") || !headers.contains_key("transfer-encoding")
            {
                return None;
            }
            Some(format!(
                "{side} frames itself twice: Content-Length '{}' beside Transfer-Encoding '{}'. \
                 A sender must not send Content-Length in a message that contains \
                 Transfer-Encoding, and a chain that does not resolve the two consistently is \
                 where request smuggling and response splitting live",
                crate::helpers::headers::joined_field_lines_shown(headers, "content-length"),
                crate::helpers::headers::joined_field_lines_shown(headers, "transfer-encoding"),
            ))
        };

        let mut out = Vec::new();
        if let Some(message) = section(&tx.request.headers, "Request") {
            out.push(
                ctx.by_client()
                    .report_with(&CONTENT_LENGTH_FORBIDDEN, message),
            );
        }
        if let Some(resp) = &tx.response {
            if let Some(message) = section(&resp.headers, "Response") {
                out.push(
                    ctx.by_server()
                        .report_with(&CONTENT_LENGTH_FORBIDDEN, message),
                );
            }
        }
        out
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ContentLengthVsTransferEncoding;

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    #[rstest]
    #[case(vec![("content-length", "10"), ("transfer-encoding", "chunked")], true)]
    #[case(vec![("content-length", "10")], false)]
    #[case(vec![("transfer-encoding", "chunked")], false)]
    #[case(vec![], false)]
    fn check_request_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ContentLengthVsTransferEncoding;

        use crate::test_helpers::make_test_transaction;
        let mut tx = make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(header_pairs.as_slice());
        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );

        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    /// Both directions report the one id, and it arrives as an `error`: the
    /// framing entries of the `Content-Length` subject are ranked together,
    /// and this is the one with request smuggling behind it.
    #[test]
    fn either_direction_reports_the_framing_id_as_an_error() {
        let both = &[("content-length", "10"), ("transfer-encoding", "chunked")];
        let mut request = crate::test_helpers::make_test_transaction();
        request.request.headers = crate::test_helpers::make_headers_from_pairs(both);
        let response = crate::test_helpers::make_test_transaction_with_response(200, both);

        for tx in [request, response] {
            let found = crate::test_helpers::run_rule(
                &ContentLengthVsTransferEncoding,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "content_length_vs_transfer_encoding",
                ]),
            )
            .expect("a finding");
            assert_eq!(found.violation, "content_length_forbidden");
            assert_eq!(found.severity, crate::lint::Severity::Error);
        }
    }

    #[rstest]
    #[case(vec![("content-length", "10"), ("transfer-encoding", "chunked")], true)]
    #[case(vec![("content-length", "10")], false)]
    #[case(vec![("transfer-encoding", "chunked")], false)]
    #[case(vec![], false)]
    fn check_response_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ContentLengthVsTransferEncoding;

        let status = 200;
        use crate::test_helpers::make_test_transaction_with_response;
        let tx = make_test_transaction_with_response(status, &header_pairs);
        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );

        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    /// **Both sections are read, and the first no longer answers for the
    /// second.** The body applied the check to the request and `return`ed, so a
    /// transaction whose two halves each framed themselves twice reported the
    /// client alone and `--about server` was silent. That is the transaction a
    /// smuggling probe produces: the request is written to find out how a chain
    /// resolves two framings, and the response that comes back carries the same
    /// pair.
    #[test]
    fn a_transaction_framed_twice_at_both_ends_reports_both_senders() {
        let both = &[("content-length", "10"), ("transfer-encoding", "chunked")];
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, both);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(both);
        let found = crate::test_helpers::run_rule_all(
            &ContentLengthVsTransferEncoding,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "content_length_vs_transfer_encoding",
            ]),
        );
        assert_eq!(
            found.len(),
            2,
            "{:?}",
            found.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
        let parties: Vec<_> = found.iter().filter_map(|v| v.party).collect();
        assert!(parties.contains(&crate::lint::Party::Client), "{parties:?}");
        assert!(parties.contains(&crate::lint::Party::Server), "{parties:?}");
    }

    /// The sentence names the section and both values. Two findings of one
    /// entry on one transaction would otherwise be one sentence printed twice,
    /// and an operator reading the report could not tell which message either
    /// of them was about.
    #[test]
    fn the_finding_names_the_section_and_the_two_values() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("content-length", "0"),
                ("transfer-encoding", "gzip, chunked"),
            ],
        );
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("content-length", "10"),
            ("transfer-encoding", "chunked"),
        ]);
        let found = crate::test_helpers::run_rule_all(
            &ContentLengthVsTransferEncoding,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "content_length_vs_transfer_encoding",
            ]),
        );
        let messages: Vec<&String> = found.iter().map(|v| &v.message).collect();
        assert!(
            messages.iter().any(|m| m.starts_with(
                "Request frames itself twice: Content-Length '10' beside Transfer-Encoding \
                 'chunked'."
            )),
            "{messages:?}"
        );
        assert!(
            messages.iter().any(|m| m.starts_with(
                "Response frames itself twice: Content-Length '0' beside Transfer-Encoding \
                 'gzip, chunked'."
            )),
            "{messages:?}"
        );
    }

    #[test]
    fn needs_no_response() {
        let rule = ContentLengthVsTransferEncoding;
        assert!(!rule.needs_response());
    }
}
