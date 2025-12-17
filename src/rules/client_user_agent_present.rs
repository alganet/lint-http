// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ClientUserAgentPresent;

impl Rule for ClientUserAgentPresent {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "client_user_agent_present"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        if !tx.request.headers.contains_key("user-agent") {
            Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Request missing User-Agent header".into(),
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
    #[case(vec![], true, Some("Request missing User-Agent header"))]
    #[case(vec![("user-agent", "curl/7.68.0")], false, None)]
    fn check_request_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
        #[case] expected_message: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = ClientUserAgentPresent;

        use crate::test_helpers::make_test_transaction;
        let mut tx = make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(header_pairs.as_slice());
        let violation =
            rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());

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
}
