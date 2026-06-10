// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ClientRequestTargetFormChecks;

impl Rule for ClientRequestTargetFormChecks {
    type Config = ();

    fn id(&self) -> &'static str {
        "client_request_target_form_checks"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
        _engine: &crate::rules::RuleConfigEngine,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let method = tx.request.method.as_str();
        let target = tx.request.uri.as_str();

        // Asterisk-form is only valid for OPTIONS
        if target == "*" && method != "OPTIONS" {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Asterisk ('*') request-target is only valid for OPTIONS requests".into(),
            });
        }

        // Detect absolute-form: contains scheme with '://'
        let is_absolute = target.contains("://");
        // Detect origin-form: starts with '/'
        let is_origin = target.starts_with('/');
        // Detect authority-form candidate: not origin, not absolute, not '*'
        let is_authority_like = !is_absolute && !is_origin && !target.is_empty() && target != "*";

        if method == "CONNECT" {
            // CONNECT must use authority-form
            if !is_authority_like {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "CONNECT requests MUST use authority-form (host[:port]) as the request-target".into(),
                });
            }
        } else {
            // Non-CONNECT must NOT use authority-form
            if is_authority_like {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Authority-form (host[:port]) is only valid with CONNECT requests"
                        .into(),
                });
            }

            // Absolute-form is allowed when speaking to a proxy; we cannot reliably
            // determine whether the client intended a proxy vs origin server here,
            // so we do not flag absolute-form in the general case.
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("CONNECT", "example.com:443", false)]
    #[case("CONNECT", "example.com", false)]
    #[case("CONNECT", "https://example.com/", true)]
    #[case("CONNECT", "/path", true)]
    #[case("OPTIONS", "*", false)]
    #[case("GET", "*", true)]
    #[case("GET", "example.com:443", true)]
    #[case("GET", "http://example.com/path", false)]
    #[case("GET", "/resource", false)]
    fn check_request_target_form(
        #[case] method: &str,
        #[case] uri: &str,
        #[case] expect_violation: bool,
    ) {
        let rule = ClientRequestTargetFormChecks;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = method.into();
        tx.request.uri = uri.into();

        let config = crate::test_helpers::make_test_config_with_severity(rule.id(), "error");

        let violation = rule.check(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
            &crate::rules::RuleConfigEngine::new(),
        );

        if expect_violation {
            assert!(
                violation.is_some(),
                "expected violation for {} {}",
                method,
                uri
            );
            let v = violation.unwrap();
            assert_eq!(v.rule, "client_request_target_form_checks");
        } else {
            assert!(
                violation.is_none(),
                "unexpected violation for {} {}",
                method,
                uri
            );
        }
    }

    #[test]
    fn scope_is_client() {
        let rule = ClientRequestTargetFormChecks;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        // Enable the rule as it would be in a user's config
        crate::test_helpers::enable_rule(&mut cfg, "client_request_target_form_checks");
        // Should validate and produce an engine without error
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
