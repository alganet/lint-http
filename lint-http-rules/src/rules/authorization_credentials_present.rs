// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct AuthorizationCredentialsPresent;

impl Rule for AuthorizationCredentialsPresent {
    fn id(&self) -> &'static str {
        "authorization_credentials_present"
    }

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
                match hv.to_str() {
                    Ok(s) => {
                        // The Authorization value is credentials — an auth-scheme with its
                        // authentication information — which is the structure validated here.
                        // The "credentials must actually be present" half is scheme-derived
                        // (the framework grammar permits a bare scheme); the helper owns that
                        // reasoning and the §11.4 structure cite.
                        // cite(RFC 9110 § 11.6.2): "Its value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested"
                        if let Err(msg) = crate::helpers::auth::validate_authorization_syntax(s) {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: ctx.severity,
                                message: format!("Invalid Authorization header: {}", msg),
                            });
                        }
                    }
                    Err(_) => {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: ctx.severity,
                            message: "Authorization header contains non-UTF8 value".into(),
                        })
                    }
                }
            }
            None
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "The `Authorization` request header field MUST include an authentication scheme followed by credentials. This rule flags requests where the header is empty, contains an invalid auth-scheme token, or is missing credentials after the scheme. Ensuring credentials are present helps detect malformed or truncated authorization attempts."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("11.6.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.2",
                note: "Authorization",
            },
            crate::rules::SpecRef {
                spec: "RFC 7617",
                section: None,
                url: "https://www.rfc-editor.org/rfc/rfc7617.html",
                note: "Basic Authentication",
            },
            crate::rules::SpecRef {
                spec: "RFC 6750",
                section: None,
                url: "https://www.rfc-editor.org/rfc/rfc6750.html",
                note: "The OAuth 2.0 Authorization Framework: Bearer Token Usage",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nAuthorization: Bearer abc123",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nAuthorization: Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/resource\", response=\"d41d8cd98f00b204e9800998ecf8427e\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nAuthorization: Basic",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nAuthorization: B@sic abc",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &AuthorizationCredentialsPresent;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="), false)]
    #[case(Some("Bearer abc123"), false)]
    #[case(Some("Digest username=\"Mufasa\", realm=\"test\""), false)]
    #[case(Some(""), true)]
    #[case(Some(" "), true)]
    #[case(Some("Basic"), true)]
    #[case(Some("Basic "), true)]
    #[case(Some("B@sic xyz"), true)]
    #[case(None, false)]
    fn check_authorization_cases(
        #[case] header: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = AuthorizationCredentialsPresent;
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
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn non_utf8_header_reports_violation() -> anyhow::Result<()> {
        let rule = AuthorizationCredentialsPresent;
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
        assert!(msg.contains("non-UTF8") || msg.contains("Invalid Authorization"));
        Ok(())
    }

    #[test]
    fn multiple_authorization_headers_one_invalid_is_violation() -> anyhow::Result<()> {
        let rule = AuthorizationCredentialsPresent;
        use crate::test_helpers::make_test_transaction;
        use hyper::header::HeaderValue;

        let mut tx = make_test_transaction();
        tx.request.headers.append(
            "authorization",
            HeaderValue::from_static("Bearer goodtoken"),
        );
        tx.request
            .headers
            .append("authorization", HeaderValue::from_static("Basic"));

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "authorization_credentials_present");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn scope_is_client() {
        let rule = AuthorizationCredentialsPresent;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }

    /// The field lines of an example, with its start line dropped — and checked,
    /// not assumed: this rule is request-scoped, so a response-shaped example
    /// added later would have its fields filed onto the request, where a guard
    /// could judge a value the rule never sees.
    fn published_fields(snippet: &str) -> Vec<(&str, &str)> {
        let mut lines = snippet.lines();
        let start = lines.next().expect("an example has a start line");
        assert!(
            !start.starts_with("HTTP/"),
            "a response-shaped example cannot be checked by these guards: {start:?}"
        );
        lines
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                l.split_once(": ")
                    .unwrap_or_else(|| panic!("not a header line: {l:?}"))
            })
            .collect()
    }

    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, Rule as _};
        let rule = AuthorizationCredentialsPresent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        let mut saw_a_finding = false;
        for ex in rule.examples() {
            let tx = crate::test_helpers::make_test_transaction_with_headers(&published_fields(
                ex.snippet,
            ));
            let found = crate::test_helpers::run_rule(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            );
            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule reports its Compliant example {:?}: {found:?}",
                    ex.snippet
                ),
                Compliance::NonCompliant => {
                    found.unwrap_or_else(|| {
                        panic!("rule accepts its NonCompliant example {:?}", ex.snippet)
                    });
                    saw_a_finding = true;
                }
            }
        }
        assert!(saw_a_finding, "no published example produced a finding");
    }

    /// This rule reads a credential only as far as "a scheme, then something",
    /// so every scheme-specific defect in a value it publishes is invisible to
    /// it. The published Digest credential named two parameters of the five its
    /// own scheme rule requires, and was labelled `Compliant` in the docs the
    /// whole time. The scheme owners judge these values now; each declines on a
    /// value belonging to the other scheme, so both run over every example.
    #[test]
    fn published_credentials_satisfy_the_rules_that_own_their_schemes() {
        use crate::rules::bearer_token_syntax::BearerTokenSyntax;
        use crate::rules::digest_auth_valid::DigestAuthValid;
        use crate::rules::{Compliance, Rule as _};

        let digest = DigestAuthValid;
        let bearer = BearerTokenSyntax;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&[digest.id(), bearer.id()]);
        let history = crate::transaction_history::TransactionHistory::empty();

        for ex in AuthorizationCredentialsPresent.examples() {
            if ex.compliance != Compliance::Compliant {
                continue;
            }
            let tx = crate::test_helpers::make_test_transaction_with_headers(&published_fields(
                ex.snippet,
            ));
            for owner in [&digest as &dyn crate::rules::Rule, &bearer] {
                let found = crate::test_helpers::run_rule(owner, &tx, &history, &cfg);
                assert!(
                    found.is_none(),
                    "a Compliant example publishes a credential {} rejects {:?}: {found:?}",
                    owner.id(),
                    ex.snippet
                );
            }
        }
    }
}
