// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageBasicAuthBase64Validity;

impl Rule for MessageBasicAuthBase64Validity {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_basic_auth_base64_validity"
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
        for hv in tx.request.headers.get_all("authorization").iter() {
            match hv.to_str() {
                Ok(s) => {
                    let mut parts = s.splitn(2, char::is_whitespace);
                    let scheme = parts.next().unwrap_or("").trim();
                    if scheme.eq_ignore_ascii_case("Basic") {
                        let creds = parts.next().unwrap_or("").trim();
                        if creds.is_empty() {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: "Basic Authorization missing credentials".into(),
                            });
                        }
                        if let Err(msg) = crate::helpers::auth::validate_basic_credentials(creds) {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!("Invalid Basic credentials: {} (RFC 7617)", msg),
                            });
                        }
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
    use base64::Engine;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    #[rstest]
    #[case(Some("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="), false)]
    #[case(Some("Basic not-base64"), true)]
    #[case(Some("Basic YWJj"), true)] // 'abc' -> missing colon
    #[case(Some("Bearer abc"), false)]
    #[case(None, false)]
    fn check_basic_cases(
        #[case] header: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageBasicAuthBase64Validity;
        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(h) = header {
            tx.request
                .headers
                .append("authorization", HeaderValue::from_str(h)?);
        }

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        if expect_violation {
            assert!(v.is_some(), "expected violation for header '{:?}'", header);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for header '{:?}': {:?}",
                header,
                v
            );
        }
        Ok(())
    }

    #[test]
    fn basic_with_ctl_in_password_reports_violation() {
        let creds = b"user:\x01pass";
        let enc = base64::engine::general_purpose::STANDARD.encode(creds);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            HeaderValue::from_str(&format!("Basic {}", enc)).unwrap(),
        );
        let rule = MessageBasicAuthBase64Validity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("control"));
    }

    #[test]
    fn multiple_auth_headers_one_invalid_is_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            HeaderValue::from_static("Bearer goodtoken"),
        );
        tx.request.headers.append(
            "authorization",
            HeaderValue::from_static("Basic not-base64"),
        );
        let rule = MessageBasicAuthBase64Validity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn missing_credentials_reports_violation() {
        let mut tx1 = crate::test_helpers::make_test_transaction();
        tx1.request
            .headers
            .append("authorization", HeaderValue::from_static("Basic"));
        let rule = MessageBasicAuthBase64Validity;
        let v1 = rule.check_transaction(&tx1, None, &crate::test_helpers::make_test_rule_config());
        assert!(v1.is_some());
        assert!(v1.unwrap().message.contains("missing credentials"));

        let mut tx2 = crate::test_helpers::make_test_transaction();
        tx2.request
            .headers
            .append("authorization", HeaderValue::from_static("Basic "));
        let v2 = rule.check_transaction(&tx2, None, &crate::test_helpers::make_test_rule_config());
        assert!(v2.is_some());
        assert!(v2.unwrap().message.contains("missing credentials"));
    }

    #[test]
    fn non_utf8_authorization_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            HeaderValue::from_bytes(b"Basic \xff").unwrap(),
        );
        let rule = MessageBasicAuthBase64Validity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-UTF8"));
    }

    #[test]
    fn basic_lowercase_scheme_is_accepted() {
        // scheme is case-insensitive
        let creds = b"Aladdin:open sesame";
        let enc = base64::engine::general_purpose::STANDARD.encode(creds);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            HeaderValue::from_str(&format!("basic {}", enc)).unwrap(),
        );
        let rule = MessageBasicAuthBase64Validity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn basic_empty_password_allowed() {
        // 'user:' should be allowed (empty password)
        let creds = b"user:";
        let enc = base64::engine::general_purpose::STANDARD.encode(creds);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            HeaderValue::from_str(&format!("Basic {}", enc)).unwrap(),
        );
        let rule = MessageBasicAuthBase64Validity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_basic_auth_base64_validity");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
