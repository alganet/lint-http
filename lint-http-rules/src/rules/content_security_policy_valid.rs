// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};

/// Basic Content-Security-Policy validation focusing on directive name syntax,
/// minimal value sanity checks (quoted keywords and simple hash/nonce forms),
/// and obvious structural errors (empty header, empty directive, non-utf8).
///
/// This rule is intentionally conservative and avoids strict enforcement of
/// full CSP grammar; it aims to catch obvious syntactic problems and misuses.
pub struct ContentSecurityPolicyValid;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const CSP3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "CSP3",
    section: None,
    url: "https://www.w3.org/TR/CSP3/",
    note: "W3C Content Security Policy Level 3 — directive and source-list syntax",
};
const MDN_CONTENT_SECURITY_POLICY: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "MDN Content-Security-Policy",
    section: None,
    url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy",
    note: "Mozilla MDN overview and directive examples",
};

/// The three hash algorithms a `hash-source` may name. They were written out
/// three times, in two places each, with a message per algorithm — which is why
/// they are one list now: the check does not vary by algorithm, only the
/// example in the wording does.
// cite(CSP3 § 2.3): "hash-algorithm = "sha256" / "sha384" / "sha512""
const HASH_PREFIXES: [&str; 3] = ["sha256-", "sha384-", "sha512-"];

impl ContentSecurityPolicyValid {
    /// One `;`-separated directive: its name, then each of its source
    /// expressions.
    fn directive_defect(
        &self,
        directive: &str,
        position: usize,
        severity: crate::lint::Severity,
    ) -> Option<Violation> {
        if directive.is_empty() {
            // A trailing or doubled semicolon.
            return Some(self.violation(
                severity,
                format!(
                    "Content-Security-Policy contains empty directive at position {}",
                    position
                ),
            ));
        }

        let mut parts = directive.split_whitespace();
        let name = parts
            .next()
            .expect("split_whitespace yields at least one item since the directive is not empty");

        // A CSP directive-name is narrower than the HTTP `token`: only
        // letters, digits and `-`. Enforcing `token` here let typos like
        // `default_src` (underscore is a legal tchar) pass unflagged.
        // cite(CSP3 § 2.3): "directive-name = 1*( ALPHA / DIGIT / "-" )"
        if let Some(c) = name
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || *c == '-'))
        {
            return Some(self.violation(
                severity,
                format!(
                    "Invalid character '{}' in CSP directive-name '{}', at position {}",
                    c, name, position
                ),
            ));
        }

        parts.find_map(|source| self.source_expression_defect(source, name, severity))
    }

    /// One source expression, quoted or not.
    ///
    /// The quoted forms are checked for being closed and non-empty, and for a
    /// nonce or hash that names no value. The unquoted ones are checked for
    /// being a nonce or hash at all: those two *must* be quoted, so an unquoted
    /// one is not a source expression the policy will enforce.
    ///
    /// This is deliberately not a full source-expression grammar — the rule
    /// catches the common, obvious mistakes and says so in its description.
    fn source_expression_defect(
        &self,
        source: &str,
        directive: &str,
        severity: crate::lint::Severity,
    ) -> Option<Violation> {
        if source.starts_with('\'') {
            if !source.ends_with('\'') || source.len() < 2 {
                return Some(self.violation(
                    severity,
                    format!(
                    "Unterminated or empty single-quoted source expression '{}' in directive '{}'",
                    source, directive
                ),
                ));
            }
            let inner = &source[1..source.len() - 1];
            if inner.is_empty() {
                return Some(self.violation(
                    severity,
                    format!(
                        "Empty single-quoted source expression '{}' in directive '{}'",
                        source, directive
                    ),
                ));
            }

            if let Some(nonce) = inner.strip_prefix("nonce-") {
                if nonce.is_empty() {
                    return Some(self.violation(
                        severity,
                        format!("Empty nonce value in directive '{}'", directive),
                    ));
                }
                if nonce.chars().any(char::is_whitespace) {
                    return Some(self.violation(
                        severity,
                        format!(
                            "Invalid nonce value containing whitespace in directive '{}'",
                            directive
                        ),
                    ));
                }
            }

            if HASH_PREFIXES
                .iter()
                .any(|prefix| inner.strip_prefix(prefix) == Some(""))
            {
                return Some(self.violation(
                    severity,
                    format!("Empty hash value in directive '{}'", directive),
                ));
            }

            // Nothing below applies to a value that opens with a quote.
            return None;
        }

        if let Some(nonce) = source.strip_prefix("nonce-") {
            if nonce.is_empty() {
                return Some(self.violation(
                    severity,
                    format!("Empty nonce value in directive '{}'", directive),
                ));
            }
            return Some(self.violation(
                severity,
                "Nonce source expressions MUST be single-quoted (e.g., 'nonce-...')".into(),
            ));
        }

        let prefix = HASH_PREFIXES
            .iter()
            .find(|prefix| source.starts_with(**prefix))?;
        if source.len() == prefix.len() {
            return Some(self.violation(
                severity,
                format!("Empty hash value in directive '{}'", directive),
            ));
        }
        Some(self.violation(
            severity,
            format!(
                "Hash source expressions MUST be single-quoted (e.g., '{}...')",
                prefix
            ),
        ))
    }
}

impl RuleMeta for ContentSecurityPolicyValid {
    fn id(&self) -> &'static str {
        "content_security_policy_valid"
    }

    fn description(&self) -> &'static str {
        "Validate basic `Content-Security-Policy` syntax in responses. This rule checks that the header value is UTF-8, not empty, directives are present and well-formed (directive names follow CSP's `directive-name = 1*( ALPHA / DIGIT / \"-\" )` grammar — narrower than the HTTP `token`), and common structural issues are flagged (unterminated single-quoted keywords, empty directives due to trailing semicolons, empty nonces/hashes).\n\nThis rule is intentionally conservative: it is not a full CSP grammar validator, but catches common, obvious mistakes and misconfigurations."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[CSP3, MDN_CONTENT_SECURITY_POLICY]
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

impl Rule for ContentSecurityPolicyValid {
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
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
            let resp = tx.response.as_ref()?;

            for line in resp.headers.get_all("content-security-policy").iter() {
                let Ok(policy) = line.to_str() else {
                    return Some(self.violation(
                        ctx.severity,
                        "Content-Security-Policy header value is not valid UTF-8".into(),
                    ));
                };

                if policy.trim().is_empty() {
                    return Some(self.violation(
                        ctx.severity,
                        "Content-Security-Policy header MUST not be empty".into(),
                    ));
                }

                for (position, directive) in policy.split(';').enumerate() {
                    if let Some(defect) =
                        self.directive_defect(directive.trim(), position, ctx.severity)
                    {
                        return Some(defect);
                    }
                }
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ContentSecurityPolicyValid;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    fn make_cfg() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_severity("content_security_policy_valid", "warn")
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
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(h) = header {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-security-policy", h)]);
        }

        let v = crate::test_helpers::run_rule(
            &rule,
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
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "def@ult-src 'self'",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Invalid character"));
    }

    #[test]
    fn underscore_in_directive_name_is_violation() {
        // CSP3 `directive-name = 1*( ALPHA / DIGIT / "-" )` forbids `_`; the HTTP
        // token grammar the rule used to apply accepted it, so `default_src` (a
        // plausible typo of `default-src`) slipped through unflagged.
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "default_src 'self'",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Invalid character") && v.message.contains('_'));
    }

    #[test]
    fn trailing_semicolon_reports_empty_directive() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "default-src 'self'; ",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("empty directive"));
    }

    #[test]
    fn unterminated_single_quote_is_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "default-src 'self",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Unterminated"));
    }

    #[test]
    fn empty_single_quoted_keyword_is_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "default-src ''",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
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
        crate::test_helpers::enable_rule(&mut cfg, "content_security_policy_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn non_utf8_header_is_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let bad = HeaderValue::from_bytes(&[0xff]).unwrap();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        headers.insert("content-security-policy", bad);
        tx.response.as_mut().unwrap().headers = headers;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("not valid UTF-8"));
    }

    #[test]
    fn empty_nonce_reports_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src nonce-",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Empty nonce value"));
    }

    #[test]
    fn empty_hash_reports_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src sha256-",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Empty hash value"));
    }

    #[test]
    fn multiple_header_fields_with_one_invalid_reports_violation() {
        let rule = ContentSecurityPolicyValid;
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

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Invalid character"));
    }

    #[test]
    fn scope_and_id_are_expected() {
        let rule = ContentSecurityPolicyValid;
        assert_eq!(rule.id(), "content_security_policy_valid");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn whitespace_only_header_is_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-security-policy", "   ")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("MUST not be empty"));
    }

    #[test]
    fn consecutive_semicolons_reports_empty_directive() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "default-src 'self';;;script-src 'self'",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("empty directive"));
    }

    #[test]
    fn nonce_with_whitespace_is_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src nonce-abc def",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("single-quoted"));
    }

    #[test]
    fn quoted_nonce_with_whitespace_is_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'nonce-abc def'",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Invalid nonce value") || v.message.contains("Unterminated"));
    }

    #[test]
    fn quoted_empty_nonce_reports_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'nonce-'",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Empty nonce value"));
    }

    #[test]
    fn unquoted_hash_reports_single_quoted_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src sha256-abc",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("single-quoted"));
    }

    #[test]
    fn quoted_empty_hash_reports_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'sha256-'",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Empty hash value"));
    }

    #[test]
    fn unquoted_sha384_reports_single_quoted_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src sha384-abc",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("single-quoted"));
    }

    #[test]
    fn quoted_sha512_empty_hash_reports_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'sha512-'",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Empty hash value"));
    }

    #[test]
    fn unquoted_sha512_reports_single_quoted_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src sha512-abc",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("single-quoted"));
    }

    #[test]
    fn quoted_hash_is_accepted() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'sha256-abc' https://example.com",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "unexpected violation: {:?}", v);
    }

    #[test]
    fn quoted_sha384_is_accepted() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'sha384-abc' https://example.com",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "unexpected violation: {:?}", v);
    }

    #[test]
    fn quoted_sha512_is_accepted() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'sha512-abc' https://example.com",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "unexpected violation: {:?}", v);
    }

    #[test]
    fn quoted_nonce_and_hashes_accepted() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'nonce-abc' 'sha256-abc' 'sha384-abc' 'sha512-abc' default-src 'self'",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "unexpected violation: {:?}", v);
    }

    #[test]
    fn quoted_sha384_empty_hash_reports_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src 'sha384-'",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Empty hash value"));
    }

    #[test]
    fn unquoted_sha384_empty_hash_reports_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src sha384-",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Empty hash value"));
    }

    #[test]
    fn unquoted_sha512_empty_hash_reports_violation() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-security-policy",
            "script-src sha512-",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap();
        assert!(v.message.contains("Empty hash value"));
    }

    #[test]
    fn response_absent_returns_none() {
        let rule = ContentSecurityPolicyValid;
        let cfg = make_cfg();
        let tx = crate::test_helpers::make_test_transaction();
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }
}
