// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ClientAcceptEncodingPresent;

impl Rule for ClientAcceptEncodingPresent {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "client_accept_encoding_present"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        if !tx.request.headers.contains_key("accept-encoding") {
            Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Request missing Accept-Encoding header".into(),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(true)]
    #[case(false)]
    fn check_request_accept_encoding_header(#[case] header_present: bool) -> anyhow::Result<()> {
        let rule = ClientAcceptEncodingPresent;
        let tx = if header_present {
            crate::test_helpers::make_test_transaction_with_headers(&[("accept-encoding", "gzip")])
        } else {
            crate::test_helpers::make_test_transaction()
        };
        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        if header_present {
            assert!(violation.is_none());
        } else {
            assert!(violation.is_some());
            assert_eq!(
                violation.map(|v| v.message),
                Some("Request missing Accept-Encoding header".to_string())
            );
        }
        Ok(())
    }

    #[test]
    fn scope_is_client() {
        let rule = ClientAcceptEncodingPresent;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }
}
