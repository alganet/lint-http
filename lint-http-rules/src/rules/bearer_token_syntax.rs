// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct BearerTokenSyntax;

impl Rule for BearerTokenSyntax {
    fn id(&self) -> &'static str {
        "bearer_token_syntax"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
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

            // Split scheme and credentials. Auth-scheme names match case-insensitively.
            // cite(RFC 9110 § 11.1): "It uses a case-insensitive token to identify the authentication scheme"
            let mut parts = s.trim().splitn(2, char::is_whitespace);
            let scheme = parts.next().unwrap_or("").trim();
            if scheme.eq_ignore_ascii_case("bearer") {
                // `credentials = "Bearer" 1*SP b64token` requires a non-empty b64token
                // after the scheme, which is what the empty check and the helper call
                // enforce; the b64token grammar itself is owned by helpers::auth (§2.1).
                // cite(RFC 6750 § 2.1): "credentials = "Bearer" 1*SP b64token"
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

    fn description(&self) -> &'static str {
        "Validate `Authorization: Bearer <token>` header values. The Bearer token MUST be present, MUST NOT contain whitespace, and MUST conform to the `token68`-like form used for credential tokens (characters from the set ALPHA / DIGIT / \"-\" / \".\" / \"_\" / \"~\" / \"+\" / \"/\" followed by optional trailing `=` padding). Malformed Bearer tokens can lead to authentication failures or token parsing issues."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 6750",
                section: Some("2.1"),
                url: "https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1",
                note: "Bearer credentials — `credentials = \"Bearer\" 1*SP b64token`; the Authorization header form and grammar for the Bearer scheme",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("11.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-11.2",
                note: "token68 — the current auth framework's credential-token grammar, defined identically to RFC 6750's b64token; anchors the shape in a live spec (RFC 6750 references the obsolete RFC 2617). Replaces a stale RFC 7235 pointer.",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET / HTTP/1.1\nAuthorization: Bearer abc123",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(whitespace in token)"),
                snippet: "GET / HTTP/1.1\nAuthorization: Bearer a b",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(invalid character `@`)"),
                snippet: "GET / HTTP/1.1\nAuthorization: Bearer a@b",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &BearerTokenSyntax;

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
        let rule = BearerTokenSyntax;
        use crate::test_helpers::make_test_transaction;
        use hyper::header::HeaderValue;

        let mut tx = make_test_transaction();
        if let Some(h) = header {
            tx.request
                .headers
                .append("authorization", HeaderValue::from_str(h)?);
        }

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
        let rule = BearerTokenSyntax;
        use crate::test_helpers::make_test_transaction;
        use hyper::header::HeaderValue;

        let mut tx = make_test_transaction();
        tx.request.headers.append(
            "authorization",
            HeaderValue::from_bytes(b"Bearer \xff").unwrap(),
        );

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
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
        crate::test_helpers::enable_rule(&mut cfg, "bearer_token_syntax");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn scheme_case_insensitive_ok() {
        let rule = BearerTokenSyntax;
        use crate::test_helpers::make_test_transaction;
        use hyper::header::HeaderValue;

        let mut tx = make_test_transaction();
        tx.request
            .headers
            .append("authorization", HeaderValue::from_static("bearer abc123"));

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn multiple_authorization_headers_one_invalid_is_violation() {
        let rule = BearerTokenSyntax;
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

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn token_with_eq_in_middle_is_violation() {
        let rule = BearerTokenSyntax;
        use crate::test_helpers::make_test_transaction;
        use hyper::header::HeaderValue;

        let mut tx = make_test_transaction();
        tx.request
            .headers
            .append("authorization", HeaderValue::from_static("Bearer ab=c"));

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("Invalid Bearer token") || msg.contains("padding"));
    }

    #[test]
    fn token_starting_with_eq_is_violation() {
        let rule = BearerTokenSyntax;
        use crate::test_helpers::make_test_transaction;
        use hyper::header::HeaderValue;

        let mut tx = make_test_transaction();
        tx.request
            .headers
            .append("authorization", HeaderValue::from_static("Bearer =abc"));

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn scope_is_client() {
        let rule = BearerTokenSyntax;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }
}
