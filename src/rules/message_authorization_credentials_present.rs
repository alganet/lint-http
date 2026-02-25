// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageAuthorizationCredentialsPresent;

impl Rule for MessageAuthorizationCredentialsPresent {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_authorization_credentials_present"
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
            match hv.to_str() {
                Ok(s) => {
                    if let Err(msg) = crate::helpers::auth::validate_authorization_syntax(s) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Invalid Authorization header: {}", msg),
                        });
                    }
                }
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Authorization header contains non-UTF8 value".into(),
                    })
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
    #[case(Some("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="), false)]
    #[case(Some("Bearer abc123"), false)]
    #[case(Some("Digest username=\"Mufasa\", realm=\"test\""), false)]
    #[case(Some(""), true)]
    #[case(Some(" "), true)]
    #[case(Some("Basic"), true)]
    #[case(Some("Basic "), true)]
    #[case(Some("B@sic xyz"), true)]
    #[case(None, false)]
    fn check_authorization_cases(
        #[case] header: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageAuthorizationCredentialsPresent;
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
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn non_utf8_header_reports_violation() -> anyhow::Result<()> {
        let rule = MessageAuthorizationCredentialsPresent;
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
        assert!(msg.contains("non-UTF8") || msg.contains("Invalid Authorization"));
        Ok(())
    }

    #[test]
    fn multiple_authorization_headers_one_invalid_is_violation() -> anyhow::Result<()> {
        let rule = MessageAuthorizationCredentialsPresent;
        use crate::test_helpers::make_test_transaction;
        use hyper::header::HeaderValue;

        let mut tx = make_test_transaction();
        tx.request.headers.append(
            "authorization",
            HeaderValue::from_static("Bearer goodtoken"),
        );
        tx.request
            .headers
            .append("authorization", HeaderValue::from_static("Basic"));

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_authorization_credentials_present");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn scope_is_client() {
        let rule = MessageAuthorizationCredentialsPresent;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }
}
