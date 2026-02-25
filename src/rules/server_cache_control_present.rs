// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerCacheControlPresent;

impl Rule for ServerCacheControlPresent {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "server_cache_control_present"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        if let Some(resp) = &tx.response {
            if resp.status == 200 && !resp.headers.contains_key("cache-control") {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Response 200 without Cache-Control header".into(),
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
    #[case(200, None, true, Some("Response 200 without Cache-Control header"))]
    #[case(200, Some(("cache-control", "no-cache")), false, None)]
    #[case(404, None, false, None)]
    fn check_response_cases(
        #[case] status: u16,
        #[case] header: Option<(&str, &str)>,
        #[case] expect_violation: bool,
        #[case] expected_message: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = ServerCacheControlPresent;

        use crate::test_helpers::make_test_transaction_with_response;
        let tx = match header {
            Some((k, v)) => make_test_transaction_with_response(status, &[(k, v)]),
            None => make_test_transaction_with_response(status, &[]),
        };
        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );

        if expect_violation {
            assert!(violation.is_some());
            assert_eq!(
                violation.map(|v| v.message),
                expected_message.map(|s| s.to_string())
            );
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[test]
    fn scope_is_server() {
        let rule = ServerCacheControlPresent;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
