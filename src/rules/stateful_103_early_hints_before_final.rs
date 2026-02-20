// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Ensure `103 Early Hints` responses appear *before* the final response for
/// the same client+request-target. A `103` observed after a final response
/// for the same resource is a protocol ordering error (RFC 8297).
pub struct Stateful103EarlyHintsBeforeFinal;

impl Rule for Stateful103EarlyHintsBeforeFinal {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "stateful_103_early_hints_before_final"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Only applies to responses with status 103
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };
        if resp.status != 103 {
            return None;
        }

        let prev = previous?;

        // Only consider the same client + same request-target (conservative stateful check)
        if prev.client != tx.client {
            return None;
        }
        if prev.request.uri != tx.request.uri {
            return None;
        }

        // If the previous transaction already contained a final response (>= 200),
        // a 103 now would be out-of-order.
        if let Some(prev_resp) = &prev.response {
            if prev_resp.status >= 200 {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "103 Early Hints response observed after final response (status {}) for '{}' — 103 must precede the final response",
                        prev_resp.status, tx.request.uri
                    ),
                });
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_and_scope() {
        let r = Stateful103EarlyHintsBeforeFinal;
        assert_eq!(r.id(), "stateful_103_early_hints_before_final");
        assert_eq!(r.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn early_hints_103_after_final_is_reported() {
        let rule = Stateful103EarlyHintsBeforeFinal;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut prev = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        prev.request.uri = "/x".to_string();
        prev.client = crate::test_helpers::make_test_client();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(103, &[]);
        tx.request.uri = "/x".to_string();
        tx.client = crate::test_helpers::make_test_client();

        let v = rule.check_transaction(&tx, Some(&prev), &cfg);
        assert!(v.is_some());
        let m = v.unwrap().message;
        assert!(m.contains("103 Early Hints") && m.contains("must precede"));
    }

    #[test]
    fn early_hints_103_after_final_different_uri_is_ignored() {
        let rule = Stateful103EarlyHintsBeforeFinal;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut prev = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        prev.request.uri = "/a".to_string();
        prev.client = crate::test_helpers::make_test_client();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(103, &[]);
        tx.request.uri = "/b".to_string();
        tx.client = crate::test_helpers::make_test_client();

        let v = rule.check_transaction(&tx, Some(&prev), &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn early_hints_103_before_final_is_allowed() {
        let rule = Stateful103EarlyHintsBeforeFinal;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut prev = crate::test_helpers::make_test_transaction_with_response(103, &[]);
        prev.request.uri = "/r".to_string();
        prev.client = crate::test_helpers::make_test_client();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.uri = "/r".to_string();
        tx.client = crate::test_helpers::make_test_client();

        let v = rule.check_transaction(&tx, Some(&prev), &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "stateful_103_early_hints_before_final");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn validate_rules_missing_severity_errors() {
        // When rule is enabled but missing required 'severity', validation should fail
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "stateful_103_early_hints_before_final",
        ]);
        // Remove severity key from the rule table
        if let Some(toml::Value::Table(table)) =
            cfg.rules.get_mut("stateful_103_early_hints_before_final")
        {
            table.remove("severity");
        }

        let res = crate::rules::validate_rules(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn previous_without_response_is_ignored() {
        let rule = Stateful103EarlyHintsBeforeFinal;
        let cfg = crate::test_helpers::make_test_rule_config();

        // previous transaction exists but has no response -> rule should ignore
        let mut prev = crate::test_helpers::make_test_transaction();
        prev.request.uri = "/z".to_string();
        prev.client = crate::test_helpers::make_test_client();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(103, &[]);
        tx.request.uri = "/z".to_string();
        tx.client = crate::test_helpers::make_test_client();

        let v = rule.check_transaction(&tx, Some(&prev), &cfg);
        assert!(v.is_none());
    }
}
