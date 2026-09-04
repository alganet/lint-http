// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct AuthSchemeRegistered;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_11_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("11.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-11.1",
    note: "Authentication Scheme — `auth-scheme = token`, and where new schemes are registered",
};
const RFC_9110_16_4_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("16.4.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-16.4.1",
    note: "Authentication Scheme Registry",
};
const IANA_HTTP_AUTHENTICATION_SCHEMES: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "IANA HTTP Authentication Schemes",
    section: None,
    url: "https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml",
    note: "IANA HTTP Authentication Scheme Registry",
};

impl Rule for AuthSchemeRegistered {
    fn id(&self) -> &'static str {
        "auth_scheme_registered"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn prepare(&self, cfg: &crate::config::Config) -> anyhow::Result<crate::rules::ResolvedRule> {
        let severity = crate::rules::get_rule_severity_required(cfg, self.id())?;
        let allowed = crate::helpers::rule_config::parse_lowercased_list(
            cfg,
            self.id(),
            "allowed",
            "acceptable auth-schemes",
            "['Basic','Bearer']",
        )?;
        // The two standard keys, **after** this rule's own options, so a config
        // naming a bad option still fails on that option.
        crate::rules::validate_rule_table(cfg, self.id())?;
        Ok(crate::rules::ResolvedRule {
            severity,
            state: Box::new(crate::helpers::rule_config::AllowedList { allowed }),
        })
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            let config: &crate::helpers::rule_config::AllowedList = ctx.state();
            // Helper to check a single scheme token against allowed list
            let check_scheme =
                |hdr_name: &str, scheme: &str, allowed: &Vec<String>| -> Option<Violation> {
                    // An auth-scheme is a token; the tchar set is helper-owned.
                    // cite(RFC 9110 § 11.1): "It uses a case-insensitive token to identify the authentication scheme"
                    if let Some(c) = crate::helpers::token::find_invalid_token_char(scheme) {
                        return Some(AuthSchemeRegistered.violation(
                            ctx.severity,
                            format!("Invalid character '{}' in {} auth-scheme", c, hdr_name),
                        ));
                    }
                    // The guidance the allowlist stands for: schemes ought to be registered.
                    // The comparison is lowercase because the scheme token is case-insensitive
                    // (§11.1). Note this is checked against an operator-configured `allowed`
                    // list, not the live IANA registry — the allowlist is the operator's chosen
                    // subset of acceptable (typically registered) schemes, and §16.4.1 is where
                    // registered ones live.
                    // cite(RFC 9110 § 11.1): "New and existing authentication schemes are specified independently and ought to be registered"
                    // cite(RFC 9110 § 16.4.1): "The "Hypertext Transfer Protocol (HTTP) Authentication Scheme Registry" defines the namespace for the authentication schemes in challenges and credentials."
                    if !allowed.contains(&scheme.to_ascii_lowercase()) {
                        return Some(AuthSchemeRegistered.violation(
                            ctx.severity,
                            format!("Unrecognized auth-scheme '{}' in {}", scheme, hdr_name),
                        ));
                    }
                    None
                };

            // Check WWW-Authenticate challenges in responses
            if let Some(resp) = &tx.response {
                for hv in resp.headers.get_all("www-authenticate").iter() {
                    let Ok(s) = hv.to_str() else {
                        return Some(self.violation(
                            ctx.severity,
                            "WWW-Authenticate header contains non-UTF8 value".into(),
                        ));
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
                            return Some(self.violation(
                                ctx.severity,
                                format!("Invalid WWW-Authenticate header: {}", e),
                            ))
                        }
                    }
                }
            }

            // Check Authorization header in requests
            if let Some(hv) = tx.request.headers.get_all("authorization").iter().next() {
                let Ok(v) = hv.to_str() else {
                    return Some(self.violation(
                        ctx.severity,
                        "Authorization header contains non-UTF8 value".into(),
                    ));
                };
                // validate basic syntax first
                if let Err(defect) = crate::helpers::auth::validate_authorization_syntax(v) {
                    return Some(self.violation(
                        ctx.severity,
                        format!("Invalid Authorization header: {}", defect.message()),
                    ));
                }

                let scheme = v.split(char::is_whitespace).next().unwrap().trim();
                if let Some(vv) = check_scheme("Authorization", scheme, &config.allowed) {
                    return Some(vv);
                }
            }

            None
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "Validate authentication schemes used in `WWW-Authenticate` and `Authorization` headers. The `auth-scheme` is a `token` and SHOULD be an IANA-registered authentication scheme (for example, `Basic`, `Bearer`, `Digest`). This rule allows an operator-configured allowlist of acceptable schemes; values not present in the allowlist are flagged."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_11_1,
            RFC_9110_16_4_1,
            IANA_HTTP_AUTHENTICATION_SCHEMES,
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "WWW-Authenticate: Basic realm=\"example\"\nAuthorization: Bearer abc123",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "WWW-Authenticate: NewScheme abc=\nAuthorization: X-MyAuth abc",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &AuthSchemeRegistered;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_cfg() -> crate::config::Config {
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "auth_scheme_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![
                        toml::Value::String("basic".into()),
                        toml::Value::String("bearer".into()),
                        toml::Value::String("digest".into()),
                    ]),
                );
                t
            }),
        );
        cfg
    }

    #[rstest]
    #[case(Some("Basic realm=\"x\""), false)]
    #[case(Some("Bearer realm=\"x\""), false)]
    #[case(Some("NewScheme abc="), true)]
    #[case(Some("b@d realm=\"x\""), true)]
    #[case(None, false)]
    fn check_www_authenticate_cases(#[case] h: Option<&str>, #[case] expect_violation: bool) {
        let rule = AuthSchemeRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        if let Some(v) = h {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("www-authenticate", v)]);
        }

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
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
        let rule = AuthSchemeRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = h {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("authorization", v)]);
        }

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "auth_scheme_registered");
        cfg.rules.insert(
            "auth_scheme_registered".into(),
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
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn www_authenticate_split_error_reports_violation() {
        let rule = AuthSchemeRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("www-authenticate", " realm=\"x\"")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
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

        let rule = AuthSchemeRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let mut hm = HeaderMap::new();
        hm.insert(
            HeaderName::from_static("www-authenticate"),
            HeaderValue::from_bytes(b"Basic \xff").unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-UTF8"));
    }

    #[test]
    fn authorization_non_utf8_reports_violation() {
        use hyper::header::HeaderName;
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = AuthSchemeRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.insert(
            HeaderName::from_static("authorization"),
            HeaderValue::from_bytes(b"Basic \xff").unwrap(),
        );
        tx.request.headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-UTF8"));
    }

    #[test]
    fn authorization_missing_credentials_reports_violation() {
        let rule = AuthSchemeRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("authorization", "Basic")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Invalid Authorization header"));
    }

    #[test]
    fn parse_allowed_config_error_cases() {
        // Missing table
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "auth_scheme_registered");
        assert!(AuthSchemeRegistered.prepare(&cfg).is_err());

        // Not a table
        let mut cfg2 = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg2, "auth_scheme_registered");
        cfg2.rules.insert(
            "auth_scheme_registered".into(),
            toml::Value::String("invalid".into()),
        );
        assert!(AuthSchemeRegistered.prepare(&cfg2).is_err());

        // allowed not array
        let mut cfg3 = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg3, "auth_scheme_registered");
        cfg3.rules.insert(
            "auth_scheme_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("allowed".into(), toml::Value::String("Basic".into()));
                t
            }),
        );
        assert!(AuthSchemeRegistered.prepare(&cfg3).is_err());

        // empty allowed array
        let mut cfg4 = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg4, "auth_scheme_registered");
        cfg4.rules.insert(
            "auth_scheme_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("allowed".into(), toml::Value::Array(Vec::new()));
                t
            }),
        );
        assert!(AuthSchemeRegistered.prepare(&cfg4).is_err());

        // non-string item
        let mut cfg5 = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg5, "auth_scheme_registered");
        cfg5.rules.insert(
            "auth_scheme_registered".into(),
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
        assert!(AuthSchemeRegistered.prepare(&cfg5).is_err());

        // normalization to lowercase
        let mut cfg6 = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg6, "auth_scheme_registered");
        cfg6.rules.insert(
            "auth_scheme_registered".into(),
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
        let parsed = AuthSchemeRegistered.prepare(&cfg6).unwrap();
        let parsed: &crate::helpers::rule_config::AllowedList =
            parsed.state.downcast_ref().expect("allowed list state");
        assert_eq!(
            parsed.allowed,
            vec!["basic".to_string(), "bearer".to_string()]
        );
    }

    #[test]
    fn www_authenticate_multiple_challenges_reports_violation() {
        let rule = AuthSchemeRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "www-authenticate",
            "Basic realm=\"x\", NewScheme abc=",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn www_authenticate_multiple_header_fields_one_invalid_reports_violation() {
        use hyper::header::HeaderName;
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = AuthSchemeRegistered;
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

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn www_authenticate_case_insensitive_scheme_accepted() {
        let rule = AuthSchemeRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "www-authenticate",
            "bAsIc realm=\"x\"",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn authorization_multiple_headers_first_missing_reports_violation() {
        use hyper::header::HeaderName;
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let rule = AuthSchemeRegistered;
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

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn authorization_case_insensitive_scheme_accepted() {
        let rule = AuthSchemeRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "authorization",
            "bAsIc QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn allowed_list_case_insensitive_runtime_ok() -> anyhow::Result<()> {
        let mut cfgt = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfgt, "auth_scheme_registered");
        cfgt.rules.insert(
            "auth_scheme_registered".into(),
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
        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "www-authenticate",
            "Basic realm=\"x\"",
        )]);

        let v = crate::test_helpers::run_rule(
            &AuthSchemeRegistered,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfgt,
        );
        assert!(v.is_none());
        Ok(())
    }
}
