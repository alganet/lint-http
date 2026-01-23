// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageCookieDomainValidity;

impl Rule for MessageCookieDomainValidity {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_cookie_domain_validity"
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
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        for hv in resp.headers.get_all("set-cookie").iter() {
            let s = match hv.to_str() {
                Ok(v) => v,
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Set-Cookie header value is not valid UTF-8".into(),
                    })
                }
            };

            // split into cookie-pair and attributes
            let parts = s.split(';').map(|p| p.trim()).collect::<Vec<_>>();
            for attr in parts.iter().skip(1) {
                if attr.is_empty() {
                    continue;
                }
                let mut av = attr.splitn(2, '=');
                let key = av.next().unwrap().trim();
                let val = av.next().map(|v| v.trim()).unwrap_or("");
                if key.eq_ignore_ascii_case("domain") {
                    if val.is_empty() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Set-Cookie attribute 'Domain' requires a value".into(),
                        });
                    }
                    match crate::helpers::domain::validate_cookie_domain(val) {
                        Ok(()) => {
                            // allow leading dot but warn (this rule is correctness focused; we'll accept leading dot);
                            if val.starts_with('.') {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: "Set-Cookie 'Domain' attribute uses a leading '.' which is deprecated; prefer the registry form without leading dot".into(),
                                });
                            }
                        }
                        Err(e) => {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Invalid Set-Cookie Domain attribute '{}': {}",
                                    val, e
                                ),
                            });
                        }
                    }
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

    fn check_set_cookie(value: &str) -> Option<Violation> {
        use crate::test_helpers::make_test_transaction_with_response;
        let tx = make_test_transaction_with_response(200, &[("set-cookie", value)]);
        let rule = MessageCookieDomainValidity;
        rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config())
    }

    #[rstest]
    #[case("SID=1; Domain=example.com", false)]
    #[case("SID=1; Domain=.example.com", true)] // leading dot => warn
    #[case("SID=1; Domain=", true)]
    #[case("SID=1; Domain=192.168.0.1", true)]
    #[case("SID=1; Domain=exa_mple.com", true)]
    #[case("SID=1; Domain=example..com", true)]
    fn domain_cases(#[case] cookie: &str, #[case] expect_violation: bool) {
        let v = check_set_cookie(cookie);
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}', got none", cookie);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for '{}': {:?}",
                cookie,
                v
            );
        }
    }

    #[test]
    fn multiple_set_cookie_headers_one_invalid_reports_violation() {
        use crate::test_helpers::make_test_transaction;
        use hyper::header::HeaderValue;

        let mut tx = make_test_transaction();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[(
            "set-cookie",
            "SID=1; Domain=example.com",
        )]);
        hm.append(
            "set-cookie",
            HeaderValue::from_static("SID=2; Domain=192.168.0.1"),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,
        });

        let rule = MessageCookieDomainValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn leading_dot_reports_deprecation_message() {
        let v = check_set_cookie("SID=1; Domain=.example.com");
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("deprecated") || msg.contains("leading '.'"));
    }

    #[test]
    fn attribute_order_and_spacing_are_tolerated() {
        // Domain not first and spaces around '='
        let v = check_set_cookie("SID=1; Secure; Domain = example.com");
        assert!(v.is_none(), "unexpected violation: {:?}", v);
    }

    #[test]
    fn non_utf8_set_cookie_is_reported() -> anyhow::Result<()> {
        use crate::http_transaction::ResponseInfo;
        use crate::test_helpers::make_test_transaction;
        use hyper::header::HeaderValue;

        let mut tx = make_test_transaction();
        tx.response = Some(ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hyper::HeaderMap::new(),
        });

        // Append a non-UTF8 header value
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .append("set-cookie", HeaderValue::from_bytes(&[0xff])?);

        let rule = MessageCookieDomainValidity;
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("not valid UTF-8"));
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_cookie_domain_validity");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
