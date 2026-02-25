// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageBearerTokenFormatValidity;

impl Rule for MessageBearerTokenFormatValidity {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_bearer_token_format_validity"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        for hv in tx.request.headers.get_all("authorization").iter() {
            let s = match hv.to_str() {
                Ok(s) => s,
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Authorization header contains non-UTF8 value".into(),
                    })
                }
            };

            // split scheme and credentials
            let mut parts = s.trim().splitn(2, char::is_whitespace);
            let scheme = parts.next().unwrap_or("").trim();
            if scheme.eq_ignore_ascii_case("bearer") {
                let creds = parts.next().map(|r| r.trim()).unwrap_or("");
                if creds.is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Authorization: Bearer missing token".into(),
                    });
                }

                if let Err(msg) = crate::helpers::auth::validate_bearer_token(creds) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Invalid Bearer token: {}", msg),
                    });
                }
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
    #[case(Some("Bearer abc123"), false)]
    #[case(Some("Bearer abc.def~+/_"), false)]
    #[case(Some("Bearer abc=="), false)]
    #[case(Some("Bearer a b"), true)]
    #[case(Some("Bearer"), true)]
    #[case(Some("Bearer \"quoted\""), true)]
    #[case(Some("Bearer a@b"), true)]
    #[case(None, false)]
    fn check_bearer_cases(
        #[case] header: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageBearerTokenFormatValidity;
        use crate::test_helpers::make_test_transaction;
        use hyper::header::HeaderValue;

        let mut tx = make_test_transaction();
        if let Some(h) = header {
            tx.request
                .headers
                .append("authorization", HeaderValue::from_str(h)?);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for header={:?}", header);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for header={:?}: {:?}",
                header,
                v
            );
        }
        Ok(())
    }

    #[test]
    fn non_utf8_header_reports_violation() -> anyhow::Result<()> {
        let rule = MessageBearerTokenFormatValidity;
        use crate::test_helpers::make_test_transaction;
        use hyper::header::HeaderValue;

        let mut tx = make_test_transaction();
        tx.request.headers.append(
            "authorization",
            HeaderValue::from_bytes(b"Bearer \xff").unwrap(),
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(
            msg.contains("non-UTF8")
                || msg.contains("Invalid Bearer token")
                || msg.contains("missing token")
        );
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_bearer_token_format_validity");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn scheme_case_insensitive_ok() {
        let rule = MessageBearerTokenFormatValidity;
        use crate::test_helpers::make_test_transaction;
        use hyper::header::HeaderValue;

        let mut tx = make_test_transaction();
        tx.request
            .headers
            .append("authorization", HeaderValue::from_static("bearer abc123"));

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn multiple_authorization_headers_one_invalid_is_violation() {
        let rule = MessageBearerTokenFormatValidity;
        use crate::test_helpers::make_test_transaction;
        use hyper::header::HeaderValue;

        let mut tx = make_test_transaction();
        tx.request.headers.append(
            "authorization",
            HeaderValue::from_static("Bearer goodtoken"),
        );
        tx.request
            .headers
            .append("authorization", HeaderValue::from_static("Bearer a b"));

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
    }

    #[test]
    fn token_with_eq_in_middle_is_violation() {
        let rule = MessageBearerTokenFormatValidity;
        use crate::test_helpers::make_test_transaction;
        use hyper::header::HeaderValue;

        let mut tx = make_test_transaction();
        tx.request
            .headers
            .append("authorization", HeaderValue::from_static("Bearer ab=c"));

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("Invalid Bearer token") || msg.contains("padding"));
    }

    #[test]
    fn token_starting_with_eq_is_violation() {
        let rule = MessageBearerTokenFormatValidity;
        use crate::test_helpers::make_test_transaction;
        use hyper::header::HeaderValue;

        let mut tx = make_test_transaction();
        tx.request
            .headers
            .append("authorization", HeaderValue::from_static("Bearer =abc"));

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
    }

    #[test]
    fn scope_is_client() {
        let rule = MessageBearerTokenFormatValidity;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }
}
