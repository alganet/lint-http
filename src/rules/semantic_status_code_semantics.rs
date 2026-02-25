// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct SemanticStatusCodeSemantics;

impl Rule for SemanticStatusCodeSemantics {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "semantic_status_code_semantics"
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
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        let status = resp.status;

        // 401/WWW-Authenticate semantics (RFC 9110 §15.5.1)
        let has_www = resp.headers.contains_key("www-authenticate");
        if status == 401 && !has_www {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "401 Unauthorized responses MUST include a WWW-Authenticate header".into(),
            });
        }
        if status != 401 && has_www {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "WWW-Authenticate header present on non-401 response (status {})",
                    status
                ),
            });
        }

        // 407/Proxy-Authenticate semantics (RFC 9110 §15.6.1)
        let has_proxy = resp.headers.contains_key("proxy-authenticate");
        if status == 407 && !has_proxy {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "407 Proxy Authentication Required responses MUST include a Proxy-Authenticate header".into(),
            });
        }
        if status != 407 && has_proxy {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Proxy-Authenticate header present on non-407 response (status {})",
                    status
                ),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    #[test]
    fn id_and_scope() {
        let r = SemanticStatusCodeSemantics;
        assert_eq!(r.id(), "semantic_status_code_semantics");
        assert_eq!(r.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn missing_www_on_401_reports_violation() {
        let rule = SemanticStatusCodeSemantics;
        let tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("WWW-Authenticate"));
    }

    #[test]
    fn missing_proxy_on_407_reports_violation() {
        let rule = SemanticStatusCodeSemantics;
        let tx = crate::test_helpers::make_test_transaction_with_response(407, &[]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Proxy-Authenticate"));
    }

    #[test]
    fn www_on_401_is_ok() {
        let rule = SemanticStatusCodeSemantics;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "Basic realm=\"x\"")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn www_on_non_401_reports_violation() {
        let rule = SemanticStatusCodeSemantics;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("www-authenticate", "Basic realm=\"x\"")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-401"));
    }

    #[test]
    fn header_name_case_insensitive_is_accepted() {
        let rule = SemanticStatusCodeSemantics;
        // Uppercase header name should still be treated as present
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("WWW-AUTHENTICATE", "Basic realm=\"x\"")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn non_utf8_header_value_counts_as_present() {
        let rule = SemanticStatusCodeSemantics;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let mut hm = hyper::HeaderMap::new();
        // non-UTF8 header *value* — header name present
        hm.insert(
            "www-authenticate",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(
            v.is_none(),
            "non-UTF8 header value should still be treated as presence"
        );
    }

    #[test]
    fn proxy_authenticate_on_401_is_violation() {
        let rule = SemanticStatusCodeSemantics;
        // proxy-authenticate must be used only with 407 — rule will flag a violation.
        // Note: when a 401 is missing WWW-Authenticate the rule returns that violation
        // first; accept either message as evidence of a correctness problem.
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("proxy-authenticate", "Basic realm=\"proxy\"")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("Proxy-Authenticate") || msg.contains("WWW-Authenticate"));
    }

    #[test]
    fn www_on_407_reports_violation_even_if_proxy_present() {
        let rule = SemanticStatusCodeSemantics;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            407,
            &[
                ("proxy-authenticate", "Basic realm=\"proxy\""),
                ("www-authenticate", "Basic realm=\"x\""),
            ],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("WWW-Authenticate"));
    }

    #[test]
    fn proxy_authenticate_on_non_407_reports_violation() {
        let rule = SemanticStatusCodeSemantics;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("proxy-authenticate", "Basic realm=\"x\"")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Proxy-Authenticate"));
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "semantic_status_code_semantics",
        ]);
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
