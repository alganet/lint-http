// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use hyper::HeaderMap;

pub struct MessageAllowHeaderMethodTokens;

impl Rule for MessageAllowHeaderMethodTokens {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_allow_header_method_tokens"
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
        let check = |headers: &HeaderMap| -> Option<Violation> {
            for hv in headers.get_all("allow").iter() {
                let allow_str = match hv.to_str() {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                // Parse the Allow header value as a comma-separated list of method tokens
                for method_str in allow_str.split(',') {
                    let trimmed = method_str.trim();

                    // Skip empty values (can occur with trailing commas)
                    if trimmed.is_empty() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Allow header contains empty method token".into(),
                        });
                    }

                    // Validate that each method is a valid token
                    if let Some(c) = crate::helpers::token::find_invalid_token_char(trimmed) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Allow header contains invalid character '{}' in method token '{}'",
                                c, trimmed
                            ),
                        });
                    }
                }
            }
            None
        };

        // Request
        if let Some(v) = check(&tx.request.headers) {
            return Some(v);
        }

        // Response
        if let Some(resp) = &tx.response {
            if let Some(v) = check(&resp.headers) {
                return Some(v);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn check_allow_header_helper(allow_value: &str, is_response: bool) -> Option<Violation> {
        use crate::http_transaction::ResponseInfo;
        use crate::test_helpers::{make_test_rule_config, make_test_transaction};
        use hyper::header::HeaderValue;

        let rule = MessageAllowHeaderMethodTokens;
        let mut tx = make_test_transaction();

        // Initialize response if testing response headers
        if is_response && tx.response.is_none() {
            tx.response = Some(ResponseInfo {
                status: 200,
                version: "HTTP/1.1".into(),
                headers: HeaderMap::new(),

                body_length: None,
            });
        }

        let headers = if is_response {
            &mut tx.response.as_mut().unwrap().headers
        } else {
            &mut tx.request.headers
        };

        headers.insert(
            hyper::header::ALLOW,
            HeaderValue::from_str(allow_value).unwrap(),
        );

        rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_test_rule_config(),
        )
    }

    #[rstest]
    #[case("GET", false, false)]
    #[case("GET, POST", false, false)]
    #[case("GET, POST, PUT, DELETE", false, false)]
    #[case("GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS", true, false)]
    #[case("GET,POST", false, false)]
    #[case("GET , POST", false, false)]
    #[case("CUSTOM-METHOD", true, false)]
    #[case("GET, , POST", false, true)]
    #[case("", false, true)]
    #[case("GET POST", false, true)]
    #[case("GET, PO@T", false, true)]
    #[case("get, POST", false, false)]
    // Response header variants exercising the response branch
    #[case("GET, , POST", true, true)]
    #[case("", true, true)]
    fn test_allow_header_validation(
        #[case] allow_value: &str,
        #[case] is_response: bool,
        #[case] expect_violation: bool,
    ) {
        let violation = check_allow_header_helper(allow_value, is_response);

        if expect_violation {
            assert!(
                violation.is_some(),
                "Expected violation for Allow: {}",
                allow_value
            );
        } else {
            assert!(
                violation.is_none(),
                "Unexpected violation for Allow: {}: {:?}",
                allow_value,
                violation
            );
        }
    }

    #[test]
    fn test_violation_messages_are_meaningful() {
        // Invalid character
        let violation = check_allow_header_helper("GET, PO@T", false);
        assert!(violation.is_some());
        let msg = violation.unwrap().message;
        assert!(msg.contains("invalid character") && msg.contains("@"));

        // Empty token
        let violation = check_allow_header_helper("GET, , POST", false);
        assert!(violation.is_some());
        let msg = violation.unwrap().message;
        assert!(msg.contains("empty"));

        // Whitespace instead of comma (invalid)
        let violation = check_allow_header_helper("GET POST", false);
        assert!(violation.is_some());
        let msg = violation.unwrap().message;
        assert!(msg.contains("invalid character"));
    }

    #[test]
    fn test_scope_is_both() {
        let rule = MessageAllowHeaderMethodTokens;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn test_case_sensitive_empty_check() {
        // Ensure empty value triggers error
        let violation = check_allow_header_helper("", false);
        assert!(violation.is_some());
    }

    #[test]
    fn test_no_allow_header_returns_none() {
        // If there's no Allow header at all, the rule should pass
        use crate::test_helpers::{make_test_rule_config, make_test_transaction};

        let rule = MessageAllowHeaderMethodTokens;
        let tx = make_test_transaction();

        // Transaction has no Allow header
        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_test_rule_config(),
        );
        assert!(violation.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = MessageAllowHeaderMethodTokens;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("error".into()));
        cfg.rules.insert(
            "message_allow_header_method_tokens".into(),
            toml::Value::Table(table),
        );

        // validate_and_box should succeed without error
        let _config = rule.validate_and_box(&cfg)?;
        Ok(())
    }
}
