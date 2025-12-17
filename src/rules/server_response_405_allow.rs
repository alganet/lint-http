// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use crate::state::StateStore;

pub struct ServerResponse405Allow;

impl Rule for ServerResponse405Allow {
    fn id(&self) -> &'static str {
        "server_response_405_allow"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _state: &StateStore,
        _config: &crate::config::Config,
    ) -> Option<Violation> {
        if let Some(resp) = &tx.response {
            if resp.status == 405 && !resp.headers.contains_key("allow") {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: crate::rules::get_rule_severity(_config, self.id()),
                    message: "Response 405 without Allow header".into(),
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_test_context;
    use rstest::rstest;

    #[rstest]
    #[case(405, None, true, Some("Response 405 without Allow header"))]
    #[case(405, Some(("allow", "GET, HEAD")), false, None)]
    #[case(200, None, false, None)]
    fn check_response_cases(
        #[case] status: u16,
        #[case] header: Option<(&str, &str)>,
        #[case] expect_violation: bool,
        #[case] expected_message: Option<&str>,
    ) -> anyhow::Result<()> {
        let rule = ServerResponse405Allow;
        let (_client, state) = make_test_context();

        use crate::test_helpers::make_test_transaction_with_response;
        let header_pairs: Vec<(&str, &str)> = match header {
            Some((k, v)) => vec![(k, v)],
            None => vec![],
        };
        let tx = make_test_transaction_with_response(status, &header_pairs);
        let violation = rule.check_transaction(&tx, &state, &crate::config::Config::default());

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
