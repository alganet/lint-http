// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ContentLengthVsTransferEncoding;

impl Rule for ContentLengthVsTransferEncoding {
    fn id(&self) -> &'static str {
        "content_length_vs_transfer_encoding"
    }

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
            // "in any message" is what puts both directions in scope; the same check runs
            // over the response below.
            // cite(RFC 9112 § 6.2): "A sender MUST NOT send a Content-Length header field in any message that contains a Transfer-Encoding header field."
            //
            // The recipient side is why this is worth more than a style note. The two
            // fields give conflicting framing, recipients are told to resolve the
            // conflict one way, and disagreement between two recipients about where a
            // message ends is exactly the primitive that request smuggling and response
            // splitting are built on — so the pairing is treated as an attack signal,
            // not merely as redundancy.
            // cite(RFC 9112 § 6.3): "If a message is received with both a Transfer-Encoding and a Content-Length header field, the Transfer-Encoding overrides the Content-Length."
            // cite(RFC 9112 § 6.3): "An intermediary that chooses to forward the message MUST first remove the received Content-Length field and process the Transfer-Encoding"
            // Check request headers
            if tx.request.headers.contains_key("content-length")
                && tx.request.headers.contains_key("transfer-encoding")
            {
                return Some(self.violation(
                    ctx.severity,
                    "Both Content-Length and Transfer-Encoding present".into(),
                ));
            }

            // Check response headers if present
            if let Some(resp) = &tx.response {
                if resp.headers.contains_key("content-length")
                    && resp.headers.contains_key("transfer-encoding")
                {
                    return Some(self.violation(
                        ctx.severity,
                        "Both Content-Length and Transfer-Encoding present".into(),
                    ));
                }
            }

            None
        };
        Vec::from_iter(finding())
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Content-Length vs Transfer-Encoding")
    }

    fn description(&self) -> &'static str {
        "This rule flags messages (requests or responses) that include both `Content-Length` and `Transfer-Encoding` headers. A sender must never combine them: the two describe message framing differently, so a message carrying both says two things about where it ends.\n\nRecipients are told to let `Transfer-Encoding` win and an intermediary that forwards the message must strip the `Content-Length` first. Where that does not happen consistently, two recipients can disagree about the message boundary — the primitive behind request smuggling and response splitting — so the combination is treated as an attack signal rather than mere redundancy."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("6.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6.2",
                note: "The sender-side prohibition this rule enforces: Content-Length MUST NOT be sent in any message that contains Transfer-Encoding",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("6.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3",
                note: "The recipient side and the stakes: Transfer-Encoding overrides, a forwarding intermediary must strip the Content-Length, and such a message may be an attempt at request smuggling or response splitting",
            },
        ]
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

    #[test]
    fn scope_is_both() {
        let rule = ContentLengthVsTransferEncoding;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
