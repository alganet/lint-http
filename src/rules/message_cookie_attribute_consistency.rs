// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageCookieAttributeConsistency;

impl Rule for MessageCookieAttributeConsistency {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_cookie_attribute_consistency"
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

            // Split into cookie-pair and attribute segments
            let parts = s.split(';').map(|p| p.trim()).collect::<Vec<_>>();
            if parts.is_empty() || parts[0].is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Set-Cookie header missing cookie-pair".into(),
                });
            }

            // Validate cookie-name token
            let pair = parts[0];
            let mut split = pair.splitn(2, '=');
            let name = split.next().unwrap_or("").trim();
            if name.is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Set-Cookie cookie name is empty".into(),
                });
            }

            if let Some(c) = crate::helpers::token::find_invalid_token_char(name) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("Set-Cookie cookie-name contains invalid character: '{}'", c),
                });
            }

            // Track attributes
            let mut secure_present = false;
            let mut samesite_value: Option<String> = None;

            for attr in parts.iter().skip(1) {
                if attr.is_empty() {
                    // trailing semicolons or accidental empty attributes
                    continue;
                }

                // Attribute may be key or key=value
                let mut av = attr.splitn(2, '=');
                let key = av.next().unwrap().trim();
                let val_opt = av.next().map(|v| v.trim());

                if key.eq_ignore_ascii_case("secure") {
                    // Secure must be a flag (no '=') per RFC; consider 'Secure=...' invalid
                    if val_opt.is_some() && !val_opt.unwrap().is_empty() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Set-Cookie attribute 'Secure' must not have a value".into(),
                        });
                    }
                    secure_present = true;
                    continue;
                }

                if key.eq_ignore_ascii_case("httponly") {
                    if val_opt.is_some() && !val_opt.unwrap().is_empty() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Set-Cookie attribute 'HttpOnly' must not have a value".into(),
                        });
                    }
                    continue;
                }

                if key.eq_ignore_ascii_case("samesite") {
                    let v = match val_opt {
                        Some(v) => v,
                        None => {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: "Set-Cookie attribute 'SameSite' requires a value".into(),
                            })
                        }
                    };
                    // Accept Strict, Lax, None (case-insensitive)
                    let vnorm = v.trim().to_ascii_lowercase();
                    if vnorm != "strict" && vnorm != "lax" && vnorm != "none" {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Set-Cookie attribute 'SameSite' has invalid value: '{}'",
                                v
                            ),
                        });
                    }
                    samesite_value = Some(vnorm);
                    continue;
                }

                if key.eq_ignore_ascii_case("max-age") {
                    let v = match val_opt {
                        Some(v) => v,
                        None => {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: "Set-Cookie attribute 'Max-Age' requires a numeric value"
                                    .into(),
                            })
                        }
                    };
                    if v.parse::<i64>().is_err() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Set-Cookie attribute 'Max-Age' is not a valid integer: '{}'",
                                v
                            ),
                        });
                    }
                    continue;
                }

                if key.eq_ignore_ascii_case("expires") {
                    let v = match val_opt {
                        Some(v) => v,
                        None => {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message:
                                    "Set-Cookie attribute 'Expires' requires a HTTP-date value"
                                        .into(),
                            })
                        }
                    };
                    if !crate::http_date::is_valid_http_date(v) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Set-Cookie attribute 'Expires' is not a valid HTTP-date: '{}'",
                                v
                            ),
                        });
                    }
                    continue;
                }

                if key.eq_ignore_ascii_case("path") {
                    let v = match val_opt {
                        Some(v) => v,
                        None => {
                            // path with no value is acceptable? flag it
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: "Set-Cookie attribute 'Path' requires a value".into(),
                            });
                        }
                    };
                    if !v.starts_with('/') {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Set-Cookie attribute 'Path' should start with '/': '{}'",
                                v
                            ),
                        });
                    }
                    continue;
                }

                if key.eq_ignore_ascii_case("domain") {
                    let v = match val_opt {
                        Some(v) => v,
                        None => {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: "Set-Cookie attribute 'Domain' requires a value".into(),
                            })
                        }
                    };
                    if v.is_empty() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Set-Cookie attribute 'Domain' must not be empty".into(),
                        });
                    }
                    if v.contains(' ') {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Set-Cookie attribute 'Domain' must not contain spaces: '{}'",
                                v
                            ),
                        });
                    }
                    continue;
                }

                // Unknown attribute: don't flag by default
            }

            if let Some(sv) = samesite_value {
                if sv == "none" && !secure_present {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Set-Cookie with 'SameSite=None' must also set 'Secure'".into(),
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

    fn check_set_cookie(value: &str) -> Option<Violation> {
        use crate::test_helpers::make_test_transaction_with_response;
        let tx = make_test_transaction_with_response(200, &[("set-cookie", value)]);
        let rule = MessageCookieAttributeConsistency;
        rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        )
    }

    #[rstest]
    #[case("SID=31d4d96e407aad42; Secure; HttpOnly; Path=/; SameSite=None", false)]
    #[case("sid=abcd; Path=/login; HttpOnly", false)]
    #[case("id=1; SameSite=Strict; Secure", false)]
    #[case("id=1; SameSite=None", true)]
    #[case("id=1; SameSite=none", true)]
    #[case("id=1; SameSite=Weird", true)]
    #[case("=bad; Secure", true)]
    #[case("SID=1; Max-Age=abc", true)]
    #[case("SID=1; Max-Age=10", false)]
    #[case("SID=1; Expires=NotADate", true)]
    #[case("SID=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT", false)]
    #[case("SID=1; Path=login", true)]
    #[case("SID=1; Path", true)]
    #[case("SID=1; Domain=bad host", true)]
    #[case("SID=1; Domain", true)]
    #[case("SID=1; Secure=1", true)]
    #[case("SID=1; HttpOnly=1", true)]
    #[case("SID=1; SameSite", true)]
    #[case("SID", false)]
    #[case("", true)]
    fn set_cookie_cases(#[case] value: &str, #[case] expect_violation: bool) {
        let v = check_set_cookie(value);
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}', got none", value);
        } else {
            assert!(v.is_none(), "unexpected violation for '{}': {:?}", value, v);
        }
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = MessageCookieAttributeConsistency;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("error".into()));
        cfg.rules.insert(
            "message_cookie_attribute_consistency".into(),
            toml::Value::Table(table),
        );

        // validate_and_box should succeed without error
        let _config = rule.validate_and_box(&cfg)?;
        Ok(())
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

            body_length: None,
        });

        // Append a non-UTF8 header value
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .append("set-cookie", HeaderValue::from_bytes(&[0xff])?);

        let rule = MessageCookieAttributeConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("not valid UTF-8"));
        Ok(())
    }

    #[test]
    fn invalid_cookie_name_token_reports_char() {
        // Name containing invalid token character '@' should be reported
        let v = check_set_cookie("N@ME=1; Secure");
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("invalid character") && msg.contains("@"));
    }

    #[test]
    fn unknown_attribute_is_ignored() {
        // Unknown attribute 'Foo=bar' should not cause a violation
        let v = check_set_cookie("id=1; Foo=bar");
        assert!(v.is_none());
    }

    #[test]
    fn trailing_empty_attribute_ignored_and_path_ok() {
        // Trailing empty attribute should be skipped; Path value trimmed and checked
        let v = check_set_cookie("SID=1; ; Path= /home ");
        assert!(v.is_none());
    }

    #[test]
    fn secure_with_empty_value_is_accepted_but_secure_with_value_reports() {
        // Secure= (empty) is accepted by current implementation
        let v_ok = check_set_cookie("SID=1; Secure=");
        assert!(v_ok.is_none());

        // Secure=1 with a value is a violation (already covered in parametrized cases)
        let v_bad = check_set_cookie("SID=1; Secure=1");
        assert!(v_bad.is_some());
    }

    #[test]
    fn cookie_value_with_equals_is_valid() {
        // Cookie value containing '=' characters should be accepted
        let v = check_set_cookie("SID=abc=def; Path=/");
        assert!(v.is_none());
    }

    #[test]
    fn multiple_set_cookie_headers_one_invalid_reports_violation() -> anyhow::Result<()> {
        use crate::http_transaction::ResponseInfo;
        use crate::test_helpers::make_test_transaction;
        use hyper::header::HeaderValue;

        let mut tx = make_test_transaction();
        tx.response = Some(ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hyper::HeaderMap::new(),

            body_length: None,
        });

        // Append a valid and an invalid Set-Cookie header
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .append("set-cookie", HeaderValue::from_static("SID=1; Path=/"));
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .append("set-cookie", HeaderValue::from_static("=bad; Secure"));

        let rule = MessageCookieAttributeConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn samesite_requires_value_reports_message() {
        let v = check_set_cookie("SID=1; SameSite");
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("requires a value"));
    }

    #[test]
    fn lone_semicolon_is_missing_cookie_pair() {
        let v = check_set_cookie("; Secure");
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("missing cookie-pair"));
    }

    #[test]
    fn domain_empty_reports_violation() {
        let v = check_set_cookie("SID=1; Domain=");
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("must not be empty"));
    }

    #[test]
    fn max_age_negative_is_accepted() {
        let v = check_set_cookie("SID=1; Max-Age=-10");
        assert!(v.is_none());
    }
}
