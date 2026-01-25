// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Validate `ETag` header values: must be a single entity-tag (strong or weak quoted-string)
/// per RFC 9110 §7.6 / §8.8.3. Also flags invalid UTF-8 and multiple header fields.
pub struct MessageEtagSyntax;

impl Rule for MessageEtagSyntax {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_etag_syntax"
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
        let Some(resp) = &tx.response else {
            return None;
        };

        let mut count = 0usize;
        for hv in resp.headers.get_all("etag").iter() {
            count += 1;
            let s = match hv.to_str() {
                Ok(s) => s,
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "ETag header value is not valid UTF-8".into(),
                    })
                }
            };

            let t = s.trim();
            // '*' is not a valid ETag in responses (used only in conditional match lists)
            if t == "*" {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message:
                        "ETag header value '*' is invalid for responses; ETag must be an entity-tag"
                            .into(),
                });
            }

            if let Err(msg) = crate::helpers::headers::validate_entity_tag(t) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("ETag header invalid: {}", msg),
                });
            }
        }

        if count > 1 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Multiple ETag header fields present ({}); ETag must be a single entity-tag",
                    count
                ),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("\"abc\""), false)]
    #[case(Some("W/\"abc\""), false)]
    #[case(Some("*"), true)]
    #[case(Some("abc"), true)]
    #[case(None, false)]
    fn etag_cases(#[case] value: Option<&str>, #[case] expect_violation: bool) {
        let rule = MessageEtagSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = value {
            tx.response = Some(crate::http_transaction::ResponseInfo {
                status: 200,
                version: "HTTP/1.1".into(),
                headers: crate::test_helpers::make_headers_from_pairs(&[("etag", v)]),

                body_length: None,
            });
        }

        let cfg = crate::rules::RuleConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
        };

        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(v.is_some(), "expected violation for value={:?}", value);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for value={:?}: {:?}",
                value,
                v
            );
        }
    }

    #[test]
    fn non_utf8_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = MessageEtagSyntax;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.insert("etag", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
        });

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn multiple_etag_headers_reported() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = MessageEtagSyntax;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("etag", HeaderValue::from_static("\"a\""));
        hm.append("etag", HeaderValue::from_static("\"b\""));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
        });

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_etag_syntax");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn id_and_scope_are_expected() {
        let r = MessageEtagSyntax;
        assert_eq!(r.id(), "message_etag_syntax");
        assert_eq!(r.scope(), crate::rules::RuleScope::Server);
    }
}
