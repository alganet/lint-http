// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

#[derive(Debug, Clone)]
pub struct AuthSchemeConfig {
    pub enabled: bool,
    pub severity: crate::lint::Severity,
    pub allowed: Vec<String>,
}

fn parse_allowed_config(
    config: &crate::config::Config,
    rule_id: &str,
) -> anyhow::Result<AuthSchemeConfig> {
    let severity = crate::rules::get_rule_severity_required(config, rule_id)?;
    let enabled = crate::rules::get_rule_enabled_required(config, rule_id)?;

    let rule_cfg = config.get_rule_config(rule_id).ok_or_else(|| {
        anyhow::anyhow!(
            "rule '{}' requires configuration and a named 'allowed' array listing acceptable auth-schemes. Example in config_example.toml",
            rule_id
        )
    })?;
    let table = rule_cfg
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Configuration for rule '{}' must be a table", rule_id))?;

    let allowed_val = table.get("allowed").ok_or_else(|| {
        anyhow::anyhow!(
            "Rule '{}' requires an 'allowed' array listing allowed auth-schemes (e.g., ['Basic','Bearer'])",
            rule_id
        )
    })?;

    let arr = allowed_val.as_array().ok_or_else(|| {
        anyhow::anyhow!("'allowed' must be an array of strings (e.g., ['Basic','Bearer'])")
    })?;

    if arr.is_empty() {
        return Err(anyhow::anyhow!("'allowed' array cannot be empty"));
    }

    let mut out = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        let s = item.as_str().ok_or_else(|| {
            anyhow::anyhow!("'allowed' array item at index {} must be a string", i)
        })?;
        out.push(s.to_ascii_lowercase());
    }

    Ok(AuthSchemeConfig {
        enabled,
        severity,
        allowed: out,
    })
}

pub struct MessageAuthSchemeIanaRegistered;

impl Rule for MessageAuthSchemeIanaRegistered {
    type Config = AuthSchemeConfig;

    fn id(&self) -> &'static str {
        "message_auth_scheme_iana_registered"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn validate_and_box(
        &self,
        config: &crate::config::Config,
    ) -> anyhow::Result<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
        let parsed = parse_allowed_config(config, self.id())?;
        Ok(std::sync::Arc::new(parsed))
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Helper to check a single scheme token against allowed list
        let check_scheme =
            |hdr_name: &str, scheme: &str, allowed: &Vec<String>| -> Option<Violation> {
                if let Some(c) = crate::helpers::token::find_invalid_token_char(scheme) {
                    return Some(Violation {
                        rule: "message_auth_scheme_iana_registered".into(),
                        severity: config.severity,
                        message: format!("Invalid character '{}' in {} auth-scheme", c, hdr_name),
                    });
                }
                if !allowed.contains(&scheme.to_ascii_lowercase()) {
                    return Some(Violation {
                        rule: "message_auth_scheme_iana_registered".into(),
                        severity: config.severity,
                        message: format!("Unrecognized auth-scheme '{}' in {}", scheme, hdr_name),
                    });
                }
                None
            };

        // Check WWW-Authenticate challenges in responses
        if let Some(resp) = &tx.response {
            for hv in resp.headers.get_all("www-authenticate").iter() {
                let s = match hv.to_str() {
                    Ok(v) => v,
                    Err(_) => {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "WWW-Authenticate header contains non-UTF8 value".into(),
                        })
                    }
                };

                // split into assembled challenges
                match crate::helpers::auth::split_and_group_challenges(s) {
                    Ok(challenges) => {
                        for challenge in challenges {
                            let scheme =
                                challenge.split(char::is_whitespace).next().unwrap().trim();
                            if let Some(v) =
                                check_scheme("WWW-Authenticate", scheme, &config.allowed)
                            {
                                return Some(v);
                            }
                        }
                    }
                    Err(e) => {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Invalid WWW-Authenticate header: {}", e),
                        })
                    }
                }
            }
        }

        // Check Authorization header in requests
        if let Some(hv) = tx.request.headers.get_all("authorization").iter().next() {
            if let Ok(v) = hv.to_str() {
                // validate basic syntax first
                if let Err(e) = crate::helpers::auth::validate_authorization_syntax(v) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Invalid Authorization header: {}", e),
                    });
                }

                let scheme = v.split(char::is_whitespace).next().unwrap().trim();
                if let Some(vv) = check_scheme("Authorization", scheme, &config.allowed) {
                    return Some(vv);
                }
            } else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Authorization header contains non-UTF8 value".into(),
                });
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_cfg() -> AuthSchemeConfig {
        AuthSchemeConfig {
            enabled: true,
            severity: crate::lint::Severity::Warn,
            allowed: vec![
                "basic".to_string(),
                "bearer".to_string(),
                "digest".to_string(),
            ],
        }
    }

    #[rstest]
    #[case(Some("Basic realm=\"x\""), false)]
    #[case(Some("Bearer realm=\"x\""), false)]
    #[case(Some("NewScheme abc="), true)]
    #[case(Some("b@d realm=\"x\""), true)]
    #[case(None, false)]
    fn check_www_authenticate_cases(#[case] h: Option<&str>, #[case] expect_violation: bool) {
        let rule = MessageAuthSchemeIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        if let Some(v) = h {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("www-authenticate", v)]);
        }

        let violation = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
    }

    #[rstest]
    #[case(Some("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="), false)]
    #[case(Some("Bearer abc123"), false)]
    #[case(Some("X-MyAuth abc"), true)]
    #[case(Some("B@sic xyz"), true)]
    #[case(None, false)]
    fn check_authorization_cases(#[case] h: Option<&str>, #[case] expect_violation: bool) {
        let rule = MessageAuthSchemeIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = h {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("authorization", v)]);
        }

        let violation = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_auth_scheme_iana_registered");
        cfg.rules.insert(
            "message_auth_scheme_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![
                        toml::Value::String("Basic".into()),
                        toml::Value::String("Bearer".into()),
                    ]),
                );
                t
            }),
        );
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn www_authenticate_split_error_reports_violation() {
        let rule = MessageAuthSchemeIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("www-authenticate", " realm=\"x\"")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("Invalid WWW-Authenticate header"));
    }

    #[test]
    fn www_authenticate_non_utf8_reports_violation() {
        use hyper::header::HeaderName;
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = MessageAuthSchemeIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let mut hm = HeaderMap::new();
        hm.insert(
            HeaderName::from_static("www-authenticate"),
            HeaderValue::from_bytes(b"Basic \xff").unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-UTF8"));
    }

    #[test]
    fn authorization_non_utf8_reports_violation() {
        use hyper::header::HeaderName;
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = MessageAuthSchemeIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.insert(
            HeaderName::from_static("authorization"),
            HeaderValue::from_bytes(b"Basic \xff").unwrap(),
        );
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-UTF8"));
    }

    #[test]
    fn authorization_missing_credentials_reports_violation() {
        let rule = MessageAuthSchemeIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("authorization", "Basic")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Invalid Authorization header"));
    }

    #[test]
    fn parse_allowed_config_error_cases() {
        // Missing table
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_auth_scheme_iana_registered");
        assert!(parse_allowed_config(&cfg, "message_auth_scheme_iana_registered").is_err());

        // Not a table
        let mut cfg2 = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg2, "message_auth_scheme_iana_registered");
        cfg2.rules.insert(
            "message_auth_scheme_iana_registered".into(),
            toml::Value::String("invalid".into()),
        );
        assert!(parse_allowed_config(&cfg2, "message_auth_scheme_iana_registered").is_err());

        // allowed not array
        let mut cfg3 = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg3, "message_auth_scheme_iana_registered");
        cfg3.rules.insert(
            "message_auth_scheme_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("allowed".into(), toml::Value::String("Basic".into()));
                t
            }),
        );
        assert!(parse_allowed_config(&cfg3, "message_auth_scheme_iana_registered").is_err());

        // empty allowed array
        let mut cfg4 = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg4, "message_auth_scheme_iana_registered");
        cfg4.rules.insert(
            "message_auth_scheme_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("allowed".into(), toml::Value::Array(Vec::new()));
                t
            }),
        );
        assert!(parse_allowed_config(&cfg4, "message_auth_scheme_iana_registered").is_err());

        // non-string item
        let mut cfg5 = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg5, "message_auth_scheme_iana_registered");
        cfg5.rules.insert(
            "message_auth_scheme_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::Integer(1)]),
                );
                t
            }),
        );
        assert!(parse_allowed_config(&cfg5, "message_auth_scheme_iana_registered").is_err());

        // normalization to lowercase
        let mut cfg6 = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg6, "message_auth_scheme_iana_registered");
        cfg6.rules.insert(
            "message_auth_scheme_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![
                        toml::Value::String("BaSiC".into()),
                        toml::Value::String("BeArEr".into()),
                    ]),
                );
                t
            }),
        );
        let parsed = parse_allowed_config(&cfg6, "message_auth_scheme_iana_registered").unwrap();
        assert_eq!(
            parsed.allowed,
            vec!["basic".to_string(), "bearer".to_string()]
        );
    }

    #[test]
    fn www_authenticate_multiple_challenges_reports_violation() {
        let rule = MessageAuthSchemeIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "www-authenticate",
            "Basic realm=\"x\", NewScheme abc=",
        )]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn www_authenticate_multiple_header_fields_one_invalid_reports_violation() {
        use hyper::header::HeaderName;
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = MessageAuthSchemeIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let mut hm = HeaderMap::new();
        hm.append(
            HeaderName::from_static("www-authenticate"),
            HeaderValue::from_static("Basic realm=\"x\""),
        );
        hm.append(
            HeaderName::from_static("www-authenticate"),
            HeaderValue::from_static("NewScheme abc="),
        );
        tx.response.as_mut().unwrap().headers = hm;

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn www_authenticate_case_insensitive_scheme_accepted() {
        let rule = MessageAuthSchemeIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "www-authenticate",
            "bAsIc realm=\"x\"",
        )]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn authorization_multiple_headers_first_missing_reports_violation() {
        use hyper::header::HeaderName;
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = MessageAuthSchemeIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Basic"),
        );
        hm.append(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer abc123"),
        );
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn authorization_case_insensitive_scheme_accepted() {
        let rule = MessageAuthSchemeIanaRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "authorization",
            "bAsIc QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        )]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn allowed_list_case_insensitive_runtime_ok() -> anyhow::Result<()> {
        let mut cfgt = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfgt, "message_auth_scheme_iana_registered");
        cfgt.rules.insert(
            "message_auth_scheme_iana_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("BaSiC".into())]),
                );
                t
            }),
        );
        let parsed = parse_allowed_config(&cfgt, "message_auth_scheme_iana_registered")?;

        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "www-authenticate",
            "Basic realm=\"x\"",
        )]);

        let v = MessageAuthSchemeIanaRegistered.check_transaction(&tx, None, &parsed);
        assert!(v.is_none());
        Ok(())
    }
}
