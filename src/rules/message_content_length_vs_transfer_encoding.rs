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
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &crate::config::Config,
    ) -> Option<Violation> {
        // Check request headers
        if tx.request.headers.contains_key("content-length")
            && tx.request.headers.contains_key("transfer-encoding")
        {
            return Some(Violation {
                rule: self.id().into(),
                severity: crate::rules::get_rule_severity(config, self.id()),
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
                    severity: crate::rules::get_rule_severity(config, self.id()),
                    message: "Both Content-Length and Transfer-Encoding present".into(),
                });
            }
        }

        None
    }
}

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
        let violation = rule.check_transaction(&tx, None, &crate::config::Config::default());

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
        let violation = rule.check_transaction(&tx, None, &crate::config::Config::default());

        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }
}
