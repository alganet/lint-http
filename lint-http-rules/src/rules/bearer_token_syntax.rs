// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::auth_scheme::RFC_9110_11_2;
use crate::violations::credentials::{CREDENTIALS_MISSING, RFC_9110_11_6_2};
use crate::violations::token68::{
    bearer_token_defect, TOKEN68_BODY_EMPTY, TOKEN68_CHARACTER_FORBIDDEN,
    TOKEN68_PADDING_MALFORMED, TOKEN68_WHITESPACE_OR_CONTROL_FORBIDDEN,
};
use crate::violations::ViolationDef;

pub struct BearerTokenSyntax;

/// The defects this rule reports, and not one of them is `Bearer`'s. RFC 6750
/// § 2.1 gives the scheme `b64token`, which is § 11.2's `token68` spelled
/// again with the same alphabet — so the four grammar defects are the
/// production's, and a `WWW-Authenticate` challenge carrying a bare word
/// reports the first of them under the same id. A `Bearer` with nothing after
/// it is the framework's `credentials_missing`, which is what two other rules
/// say about the same request.
static DECLARED: &[&ViolationDef] = &[
    &TOKEN68_WHITESPACE_OR_CONTROL_FORBIDDEN,
    &TOKEN68_CHARACTER_FORBIDDEN,
    &TOKEN68_BODY_EMPTY,
    &TOKEN68_PADDING_MALFORMED,
    &CREDENTIALS_MISSING,
];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_6750_2_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6750",
    section: Some("2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1",
    note: "Bearer credentials — `credentials = \"Bearer\" 1*SP b64token`; the Authorization header form and grammar for the Bearer scheme",
};

impl RuleMeta for BearerTokenSyntax {
    fn id(&self) -> &'static str {
        "bearer_token_syntax"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
severity = "warn"
"#
    }

    fn description(&self) -> &'static str {
        "Validate `Authorization: Bearer <token>` header values. The Bearer token MUST be present, MUST NOT contain whitespace, and MUST conform to the `token68`-like form used for credential tokens (characters from the set ALPHA / DIGIT / \"-\" / \".\" / \"_\" / \"~\" / \"+\" / \"/\" followed by optional trailing `=` padding). Malformed Bearer tokens can lead to authentication failures or token parsing issues."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_6750_2_1, RFC_9110_11_2, RFC_9110_11_6_2]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
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

impl Rule for BearerTokenSyntax {
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
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
            for hv in tx.request.headers.get_all("authorization").iter() {
                let Ok(s) = hv.to_str() else {
                    return Some(self.violation(
                        ctx.severity,
                        "Authorization header contains non-UTF8 value".into(),
                    ));
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
                        // The framework's defect and not this scheme's: what
                        // must follow a scheme is `credentials`' sentence,
                        // whichever scheme was named.
                        return Some(ctx.report_with(
                            &CREDENTIALS_MISSING,
                            "Authorization: Bearer missing token".into(),
                        ));
                    }

                    if let Err(defect) = crate::helpers::auth::validate_bearer_token(creds) {
                        return Some(ctx.report_with(
                            bearer_token_defect(defect),
                            format!("Invalid Bearer token: {}", defect.message()),
                        ));
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
static REGISTRATION: &dyn crate::rules::Rule = &BearerTokenSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Five names where the rule had one, and none of them is `Bearer`'s: the
    /// token is `token68` under another spelling, and a scheme with nothing
    /// after it is the framework's defect. The whitespace row defaults a level
    /// above the rest — a space inside credentials is the value having been
    /// split or joined by something on the way, not a sender's choice.
    #[rstest]
    #[case("Bearer", "credentials_missing", crate::lint::Severity::Warn)]
    #[case(
        "Bearer a b",
        "token68_whitespace_or_control_forbidden",
        crate::lint::Severity::Error
    )]
    #[case(
        "Bearer a@b",
        "token68_character_forbidden",
        crate::lint::Severity::Warn
    )]
    #[case("Bearer ==", "token68_body_empty", crate::lint::Severity::Warn)]
    #[case(
        "Bearer ab=c",
        "token68_padding_malformed",
        crate::lint::Severity::Warn
    )]
    fn each_finding_names_the_defect_and_carries_its_severity(
        #[case] header: &str,
        #[case] violation: &str,
        #[case] severity: crate::lint::Severity,
    ) -> anyhow::Result<()> {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            hyper::header::HeaderValue::from_str(header)?,
        );
        let v = crate::test_helpers::run_rule(
            &BearerTokenSyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["bearer_token_syntax"]),
        )
        .unwrap_or_else(|| panic!("expected a finding for {header:?}"));
        assert_eq!(v.violation, violation, "{}", v.message);
        assert_eq!(v.severity, severity, "{}", v.message);
        Ok(())
    }

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
