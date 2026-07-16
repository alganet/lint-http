// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Basic Content-Security-Policy validation focusing on directive name syntax,
/// minimal value sanity checks (quoted keywords and simple hash/nonce forms),
/// and obvious structural errors (empty header, empty directive, non-utf8).
///
/// This rule is intentionally conservative and avoids strict enforcement of
/// full CSP grammar; it aims to catch obvious syntactic problems and misuses.
pub struct ServerContentSecurityPolicyValidity;

impl Rule for ServerContentSecurityPolicyValidity {
    fn id(&self) -> &'static str {
        "server_content_security_policy_validity"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        // Only check responses
        let resp = tx.response.as_ref()?;

        use crate::helpers::token::find_invalid_token_char;

        for hv in resp.headers.get_all("content-security-policy").iter() {
            // UTF-8
            let s = match hv.to_str() {
                Ok(s) => s,
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Content-Security-Policy header value is not valid UTF-8".into(),
                    });
                }
            };

            let s_trim = s.trim();
            if s_trim.is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Content-Security-Policy header MUST not be empty".into(),
                });
            }

            // Split directives on ';'
            for (i, raw_dir) in s.split(';').enumerate() {
                let dir = raw_dir.trim();
                if dir.is_empty() {
                    // Empty directive (e.g., trailing or consecutive semicolons)
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Content-Security-Policy contains empty directive at position {}",
                            i
                        ),
                    });
                }

                // Directive name is the first token up to whitespace
                let mut parts = dir.split_whitespace();
                let name = parts
                    .next()
                    .expect("split_whitespace yields at least one item since dir is not empty");

                if let Some(c) = find_invalid_token_char(name) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Invalid character '{}' in CSP directive-name '{}', at position {}",
                            c, name, i
                        ),
                    });
                }

                // Basic checks for values: ensure single-quoted keywords are closed and non-empty
                for val in parts {
                    if val.starts_with('\'') {
                        // Single-quoted token expected (e.g., 'self' or 'nonce-...')
                        if !val.ends_with('\'') || val.len() < 2 {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!("Unterminated or empty single-quoted source expression '{}' in directive '{}'", val, name),
                            });
                        }
                        let inner = &val[1..val.len() - 1];
                        if inner.is_empty() {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Empty single-quoted source expression '{}' in directive '{}'",
                                    val, name
                                ),
                            });
                        }

                        // Validate nonce/hash when present inside quoted source expression
                        if let Some(rest) = inner.strip_prefix("nonce-") {
                            if rest.is_empty() {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!("Empty nonce value in directive '{}'", name),
                                });
                            }
                            if rest.chars().any(|c: char| c.is_whitespace()) {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!("Invalid nonce value containing whitespace in directive '{}'", name),
                                });
                            }
                        }

                        if let Some(rest) = inner.strip_prefix("sha256-") {
                            if rest.is_empty() {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!("Empty hash value in directive '{}'", name),
                                });
                            }
                        } else if let Some(rest) = inner.strip_prefix("sha384-") {
                            if rest.is_empty() {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!("Empty hash value in directive '{}'", name),
                                });
                            }
                        } else if let Some(rest) = inner.strip_prefix("sha512-") {
                            if rest.is_empty() {
                                return Some(Violation {
                                    rule: self.id().into(),
                                    severity: config.severity,
                                    message: format!("Empty hash value in directive '{}'", name),
                                });
                            }
                        }
                    }

                    // Basic nonce/hash forms: allow 'nonce-<token>' and 'sha256-...'
                    if let Some(rest) = val.strip_prefix("nonce-") {
                        if rest.is_empty() {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!("Empty nonce value in directive '{}'", name),
                            });
                        }
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message:
                                "Nonce source expressions MUST be single-quoted (e.g., 'nonce-...')"
                                    .into(),
                        });
                    }

                    if let Some(rest) = val.strip_prefix("sha256-") {
                        if rest.is_empty() {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!("Empty hash value in directive '{}'", name),
                            });
                        }
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message:
                                "Hash source expressions MUST be single-quoted (e.g., 'sha256-...')"
                                    .into(),
                        });
                    } else if let Some(rest) = val.strip_prefix("sha384-") {
                        if rest.is_empty() {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!("Empty hash value in directive '{}'", name),
                            });
                        }
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message:
                                "Hash source expressions MUST be single-quoted (e.g., 'sha384-...')"
                                    .into(),
                        });
                    } else if let Some(rest) = val.strip_prefix("sha512-") {
                        if rest.is_empty() {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!("Empty hash value in directive '{}'", name),
                            });
                        }
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message:
                                "Hash source expressions MUST be single-quoted (e.g., 'sha512-...')"
                                    .into(),
                        });
                    }
                }
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "Validate basic `Content-Security-Policy` syntax in responses. This rule checks that the header value is UTF-8, not empty, directives are present and well-formed (directive names follow `token` grammar), and common structural issues are flagged (unterminated single-quoted keywords, empty directives due to trailing semicolons, empty nonces/hashes).\n\nThis rule is intentionally conservative: it is not a full CSP grammar validator, but catches common, obvious mistakes and misconfigurations."
    }

    fn rfc_references(&self) -> &'static [&'static str] {
        &[
            "W3C Content Security Policy Level 3 — directive and source-list syntax: https://www.w3.org/TR/CSP3/",
            "Mozilla MDN overview and directive examples: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Security-Policy: default-src 'self'; script-src 'nonce-abc123' https://example.com; upgrade-insecure-requests",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Security-Policy:",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Security-Policy: def@ult-src 'self'",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Security-Policy: default-src 'self';",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Security-Policy: default-src 'self",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ServerContentSecurityPolicyValidity;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    fn make_cfg() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_severity(
            "server_content_security_policy_validity",
            "warn",
        )
    }

    #[rstest]
    #[case(None, false)]
    #[case(Some("default-src 'self'"), false)]
    #[case(
        Some("script-src 'nonce-abc123' https://example.com; default-src 'none'"),
        false
    )]
    #[case(Some("upgrade-insecure-requests; default-src 'self'"), false)]
    #[case(Some(""), true)]
    fn csp_basic_cases(#[case] header: Option<&str>, #[case] expect_violation: bool) {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(h) = header {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-security-policy", h)]);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
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
    }

    #[test]
    fn invalid_directive_name_reports_violation() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "def@ult-src 'self'",
        )]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("Invalid character"));
    }

    #[test]
    fn trailing_semicolon_reports_empty_directive() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "default-src 'self'; ",
        )]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("empty directive"));
    }

    #[test]
    fn unterminated_single_quote_is_violation() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "default-src 'self",
        )]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("Unterminated"));
    }

    #[test]
    fn empty_single_quoted_keyword_is_violation() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "default-src ''",
        )]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("Empty single-quoted"));
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "server_content_security_policy_validity");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn non_utf8_header_is_violation() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();

        let bad = HeaderValue::from_bytes(&[0xff]).unwrap();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        headers.insert("content-security-policy", bad);
        tx.response.as_mut().unwrap().headers = headers;

        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("not valid UTF-8"));
    }

    #[test]
    fn empty_nonce_reports_violation() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src nonce-",
        )]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("Empty nonce value"));
    }

    #[test]
    fn empty_hash_reports_violation() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src sha256-",
        )]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("Empty hash value"));
    }

    #[test]
    fn multiple_header_fields_with_one_invalid_reports_violation() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "default-src 'self'",
        )]);
        headers.append(
            "content-security-policy",
            HeaderValue::from_static("def@ult-src 'self'"),
        );
        tx.response.as_mut().unwrap().headers = headers;

        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("Invalid character"));
    }

    #[test]
    fn scope_and_id_are_expected() {
        let rule = ServerContentSecurityPolicyValidity;
        assert_eq!(rule.id(), "server_content_security_policy_validity");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn whitespace_only_header_is_violation() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-security-policy", "   ")]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("MUST not be empty"));
    }

    #[test]
    fn consecutive_semicolons_reports_empty_directive() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "default-src 'self';;;script-src 'self'",
        )]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("empty directive"));
    }

    #[test]
    fn nonce_with_whitespace_is_violation() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src nonce-abc def",
        )]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("single-quoted"));
    }

    #[test]
    fn quoted_nonce_with_whitespace_is_violation() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'nonce-abc def'",
        )]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("Invalid nonce value") || v.message.contains("Unterminated"));
    }

    #[test]
    fn quoted_empty_nonce_reports_violation() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'nonce-'",
        )]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("Empty nonce value"));
    }

    #[test]
    fn unquoted_hash_reports_single_quoted_violation() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src sha256-abc",
        )]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("single-quoted"));
    }

    #[test]
    fn quoted_empty_hash_reports_violation() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'sha256-'",
        )]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("Empty hash value"));
    }

    #[test]
    fn unquoted_sha384_reports_single_quoted_violation() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src sha384-abc",
        )]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("single-quoted"));
    }

    #[test]
    fn quoted_sha512_empty_hash_reports_violation() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'sha512-'",
        )]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("Empty hash value"));
    }

    #[test]
    fn unquoted_sha512_reports_single_quoted_violation() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src sha512-abc",
        )]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("single-quoted"));
    }

    #[test]
    fn quoted_hash_is_accepted() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'sha256-abc' https://example.com",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "unexpected violation: {:?}", v);
    }

    #[test]
    fn quoted_sha384_is_accepted() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'sha384-abc' https://example.com",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "unexpected violation: {:?}", v);
    }

    #[test]
    fn quoted_sha512_is_accepted() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'sha512-abc' https://example.com",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "unexpected violation: {:?}", v);
    }

    #[test]
    fn quoted_nonce_and_hashes_accepted() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'nonce-abc' 'sha256-abc' 'sha384-abc' 'sha512-abc' default-src 'self'",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "unexpected violation: {:?}", v);
    }

    #[test]
    fn quoted_sha384_empty_hash_reports_violation() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'sha384-'",
        )]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("Empty hash value"));
    }

    #[test]
    fn unquoted_sha384_empty_hash_reports_violation() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src sha384-",
        )]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("Empty hash value"));
    }

    #[test]
    fn unquoted_sha512_empty_hash_reports_violation() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src sha512-",
        )]);
        let v = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            )
            .unwrap();
        assert!(v.message.contains("Empty hash value"));
    }

    #[test]
    fn response_absent_returns_none() {
        let rule = ServerContentSecurityPolicyValidity;
        let cfg = make_cfg();
        let tx = crate::test_helpers::make_test_transaction();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }
}
