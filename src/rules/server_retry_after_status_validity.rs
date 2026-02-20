// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ServerRetryAfterStatusValidity;

impl Rule for ServerRetryAfterStatusValidity {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "server_retry_after_status_validity"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        let resp = tx.response.as_ref()?;

        resp.headers.get_all("retry-after").iter().next()?;

        let status = resp.status;
        let allowed =
            status == 503 || status == 429 || crate::helpers::status::is_redirection_status(status);
        if allowed {
            return None;
        }

        Some(Violation {
            rule: self.id().into(),
            severity: config.severity,
            message: format!(
                "Retry-After header is unusual on status {}: expected 3xx redirection, 429 Too Many Requests, or 503 Service Unavailable",
                status
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(503, true, false)]
    #[case(429, true, false)]
    #[case(301, true, false)]
    #[case(308, true, false)]
    #[case(300, true, false)]
    #[case(399, true, false)]
    #[case(200, true, true)]
    #[case(500, true, true)]
    #[case(200, false, false)]
    fn retry_after_status_semantics(
        #[case] status: u16,
        #[case] with_retry_after: bool,
        #[case] expect_violation: bool,
    ) {
        let rule = ServerRetryAfterStatusValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        if with_retry_after {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("retry-after", "120")]);
        }

        let v = rule.check_transaction(&tx, None, &cfg);
        assert_eq!(v.is_some(), expect_violation);
    }

    #[test]
    fn no_response_no_violation() {
        let rule = ServerRetryAfterStatusValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = crate::test_helpers::make_test_transaction();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn id_and_scope() {
        let rule = ServerRetryAfterStatusValidity;
        assert_eq!(rule.id(), "server_retry_after_status_validity");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "server_retry_after_status_validity",
        ]);
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn violation_message_contains_status_and_expected_set() {
        let rule = ServerRetryAfterStatusValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(500, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("retry-after", "60")]);

        let v = rule
            .check_transaction(&tx, None, &cfg)
            .expect("expected violation");
        assert!(v.message.contains("status 500"));
        assert!(v.message.contains("3xx redirection"));
        assert!(v.message.contains("429"));
        assert!(v.message.contains("503"));
    }
}
