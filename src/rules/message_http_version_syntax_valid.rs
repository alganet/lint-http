// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageHttpVersionSyntaxValid;

impl Rule for MessageHttpVersionSyntaxValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_http_version_syntax_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Check request version token (now required)
        if let Some(msg) = check_version_token(&tx.request.version) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!("Request HTTP-version invalid: {}", msg),
            });
        }

        // Check response version token if response present
        if let Some(resp) = &tx.response {
            if let Some(msg) = check_version_token(&resp.version) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("Response HTTP-version invalid: {}", msg),
                });
            }
        }

        None
    }
}

// Returns Some(error_message) when invalid, or None when valid.
fn check_version_token(s: &str) -> Option<String> {
    // Must be case-sensitive "HTTP" prefix
    if !s.starts_with("HTTP/") {
        return Some(format!("invalid token '{}': must start with 'HTTP/'", s));
    }
    let rest = &s[5..];
    let parts: Vec<&str> = rest.split('.').collect();
    if parts.len() != 2 {
        return Some(format!("invalid token '{}': expected '<major>.<minor>'", s));
    }
    if parts[0].len() != 1 || parts[1].len() != 1 {
        return Some(format!(
            "invalid token '{}': major/minor must be single DIGIT each",
            s
        ));
    }
    if !parts[0].chars().all(|c| c.is_ascii_digit())
        || !parts[1].chars().all(|c| c.is_ascii_digit())
    {
        return Some(format!(
            "invalid token '{}': major/minor must be DIGIT (0-9)",
            s
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_test_rule_config;

    #[test]
    fn valid_versions_pass() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = "HTTP/1.1".into();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/2.0".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[]),
        });

        let rule = MessageHttpVersionSyntaxValid;
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn lowercase_http_is_invalid() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = "http/1.1".into();
        let rule = MessageHttpVersionSyntaxValid;
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Request HTTP-version invalid"));
    }

    #[test]
    fn multi_digit_major_or_minor_invalid() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = "HTTP/11.0".into();
        let rule = MessageHttpVersionSyntaxValid;
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_some());

        let mut tx2 = crate::test_helpers::make_test_transaction();
        tx2.request.version = "HTTP/1.10".into();
        let v2 = rule.check_transaction(&tx2, None, &make_test_rule_config());
        assert!(v2.is_some());
    }

    #[test]
    fn missing_prefix_or_dot_is_invalid() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[]),
        });
        let rule = MessageHttpVersionSyntaxValid;
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn missing_dot_is_invalid() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = "HTTP/1".into();
        let rule = MessageHttpVersionSyntaxValid;
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn non_digit_characters_invalid() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = "HTTP/1.x".into();
        let rule = MessageHttpVersionSyntaxValid;
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn extra_dot_is_invalid() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = "HTTP/1.1.1".into();
        let rule = MessageHttpVersionSyntaxValid;
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_some());
    }
    #[test]
    fn extra_dot_response_is_invalid() {
        let mut tx = crate::test_helpers::make_test_transaction();
        // Make request valid so validation reaches the response
        tx.request.version = "HTTP/1.1".into();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[]),
        });
        let rule = MessageHttpVersionSyntaxValid;
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Response HTTP-version invalid"));
    }

    #[test]
    fn empty_minor_is_invalid() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.version = "HTTP/1.".into();
        let rule = MessageHttpVersionSyntaxValid;
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn default_version_is_valid() {
        let tx = crate::test_helpers::make_test_transaction();
        let rule = MessageHttpVersionSyntaxValid;
        // make_test_transaction defaults version to "HTTP/1.1"
        let v = rule.check_transaction(&tx, None, &make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageHttpVersionSyntaxValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
