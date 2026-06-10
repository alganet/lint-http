// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageContentLengthVsTransferEncoding;

impl Rule for MessageContentLengthVsTransferEncoding {
    fn id(&self) -> &'static str {
        "message_content_length_vs_transfer_encoding"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        // Check request headers
        if tx.request.headers.contains_key("content-length")
            && tx.request.headers.contains_key("transfer-encoding")
        {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Both Content-Length and Transfer-Encoding present".into(),
            });
        }

        // Check response headers if present
        if let Some(resp) = &tx.response {
            if resp.headers.contains_key("content-length")
                && resp.headers.contains_key("transfer-encoding")
            {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Both Content-Length and Transfer-Encoding present".into(),
                });
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "This rule flags messages (requests or responses) that include both `Content-Length` and `Transfer-Encoding` headers, which can lead to ambiguous or unsafe interpretations of message length."
    }

    fn rfc_reference(&self) -> Option<&'static str> {
        Some("[RFC 9112 §6.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.2): Content-Length MUST NOT be sent when Transfer-Encoding is present")
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                snippet: "POST /submit HTTP/1.1\nHost: example.com\nContent-Length: 15\n\npayload",
            },
            Example {
                compliance: Compliance::NonCompliant,
                snippet: "POST /submit HTTP/1.1\nHost: example.com\nContent-Length: 15\nTransfer-Encoding: chunked",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageContentLengthVsTransferEncoding;

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
        let rule = MessageContentLengthVsTransferEncoding;

        use crate::test_helpers::make_test_transaction;
        let mut tx = make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(header_pairs.as_slice());
        let violation = rule.check_transaction(
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
        let rule = MessageContentLengthVsTransferEncoding;

        let status = 200;
        use crate::test_helpers::make_test_transaction_with_response;
        let tx = make_test_transaction_with_response(status, &header_pairs);
        let violation = rule.check_transaction(
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
        let rule = MessageContentLengthVsTransferEncoding;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
