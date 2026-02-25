// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageConnectionUpgrade;

impl Rule for MessageConnectionUpgrade {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_connection_upgrade"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Check request headers
        if let Some(msg) = check_connection_upgrade_map(&tx.request.headers) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: msg,
            });
        }
        // Check response headers if present
        if let Some(resp) = &tx.response {
            if let Some(msg) = check_connection_upgrade_map(&resp.headers) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: msg,
                });
            }
        }
        None
    }
}
fn connection_contains_upgrade_map(headers: &hyper::HeaderMap) -> bool {
    if let Some(val) = headers.get("connection") {
        if let Ok(s) = val.to_str() {
            if crate::helpers::headers::parse_list_header(s)
                .any(|token| token.eq_ignore_ascii_case("upgrade"))
            {
                return true;
            }
        }
    }
    false
}

fn check_connection_upgrade_map(headers: &hyper::HeaderMap) -> Option<String> {
    if connection_contains_upgrade_map(headers) && !headers.contains_key("upgrade") {
        return Some("Connection header includes 'upgrade' but Upgrade header is missing".into());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    #[rstest]
    #[case(vec![("connection", "upgrade")], true)]
    #[case(vec![("connection", "keep-alive, upgrade")], true)]
    #[case(vec![("connection", "Upgrade")], true)]
    #[case(vec![("connection", "upgrade"), ("upgrade", "websocket")], false)]
    #[case(vec![], false)]
    #[case(vec![("connection", "keep-alive")], false)]
    #[case(vec![("connection", "upgrade"), ("upgrade", "")], false)]
    fn check_request_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageConnectionUpgrade;

        use crate::test_helpers::make_test_transaction;
        let mut tx = make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(header_pairs.as_slice());
        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );

        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[rstest]
    #[case(vec![("connection", "upgrade")], true)]
    #[case(vec![("connection", "upgrade"), ("upgrade", "websocket")], false)]
    fn check_response_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageConnectionUpgrade;

        let status = 101; // Switching Protocols
        use crate::test_helpers::make_test_transaction_with_response;
        let tx = make_test_transaction_with_response(status, &header_pairs);
        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
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
        let rule = MessageConnectionUpgrade;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
