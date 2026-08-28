// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct WwwAuthenticateChallengeSyntax;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_11_6_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("11.6.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.1",
    note: "WWW-Authenticate",
};
const RFC_9110_11_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("11.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-11.3",
    note: "Challenge and Response — `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]` (RFC 7235, which defined this, is obsoleted by RFC 9110; `token68` itself is defined in §11.2)",
};

impl Rule for WwwAuthenticateChallengeSyntax {
    fn id(&self) -> &'static str {
        "www_authenticate_challenge_syntax"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // WWW-Authenticate is a response header field, so only responses are checked.
        // The challenge grammar and its validation are owned by helpers::auth (§11.3).
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
            // Only check response headers; ignore non-UTF8 header values
            if let Some(resp) = &tx.response {
                for s in crate::helpers::headers::field_lines(&resp.headers, "www-authenticate") {
                    // Group members into assembled challenges using the helper so we can
                    // test the grouping logic independently and exercise more branches.
                    // cite(RFC 9110 § 11.6.1): "The "WWW-Authenticate" response header field indicates the authentication scheme(s) and parameters applicable to the target resource."
                    let challenges = match crate::helpers::auth::split_and_group_challenges(s) {
                        Ok(c) => c,
                        Err(msg) => {
                            return Some(self.cited(&RFC_9110_11_6_1, ctx.severity, msg));
                        }
                    };

                    // Now validate each assembled challenge using helper to make it unit-testable
                    for challenge in challenges.iter() {
                        if let Err(msg) = crate::helpers::auth::validate_challenge_syntax(challenge)
                        {
                            return Some(self.violation(ctx.severity, msg));
                        }
                    }
                }
            }
            None
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "The `WWW-Authenticate` response header advertises authentication schemes that the server supports. Each challenge consists of an `auth-scheme` (a `token`) followed by optional parameters (`auth-param`) or a `token68` value.\n\nThis rule validates that each challenge:\n\n- Begins with a valid `auth-scheme` token (no illegal characters).\n- If parameters are present, each parameter is of the form `token=token` or `token=\"quoted-string\"` and quoted-strings are well-formed.\n- Token68 values are accepted as a single token-like remainder (no control characters)."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_11_6_1, RFC_9110_11_3]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Basic realm=\"example\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Bearer realm=\"example\", error=\"invalid_token\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: NewScheme abcdef123=",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: b@d realm=\"x\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Basic realm",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Basic realm=\"unfinished",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &WwwAuthenticateChallengeSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_resp(v: &str) -> crate::http_transaction::HttpTransaction {
        crate::test_helpers::make_test_transaction_with_response(401, &[("www-authenticate", v)])
    }

    #[rstest]
    #[case("Basic realm=\"example\"", false)]
    #[case("Bearer realm=\"example\", error=\"invalid_token\"", false)]
    #[case("NewScheme abcdef123=", false)]
    #[case("Basic realm=\"a,b\"", false)]
    #[case("Basic", false)]
    #[case("", true)]
    #[case(", Basic realm=\"x\"", true)]
    #[case("b@d realm=\"x\"", true)]
    #[case("Basic realm", true)]
    #[case("Basic realm=\"unfinished", true)]
    fn check_www_authenticate_cases(#[case] val: &str, #[case] expect_violation: bool) {
        let rule = WwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);
        let tx = make_resp(val);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "val='{}' expected violation", val);
        } else {
            assert!(v.is_none(), "val='{}' expected no violation", val);
        }
    }

    #[test]
    fn non_utf8_header_values_are_ignored() {
        let rule = WwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "www-authenticate",
            hyper::header::HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn parameter_before_scheme_is_violation() {
        let rule = WwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "error=\"x\"")],
        );
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
            .contains("parameter before any auth-scheme"));
    }

    #[test]
    fn trailing_empty_parameter_is_violation() {
        let rule = WwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "Basic realm=\"x\", ")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if let Some(vv) = v {
            assert!(
                vv.message.contains("empty parameter") || vv.message.contains("empty challenge")
            );
        } else {
            panic!("expected violation for trailing empty parameter");
        }
    }

    #[test]
    fn multiple_challenges_and_token68_ok() {
        let rule = WwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "Basic realm=\"a\", NewScheme abcdef=")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn token68_with_control_char_is_not_constructible() {
        // Header values containing raw control characters are rejected by hyper's HeaderValue
        // constructor; assert that such invalid header values cannot be constructed here.
        assert!(hyper::header::HeaderValue::from_bytes(b"NewScheme abc\x01").is_err());
    }

    #[test]
    fn invalid_auth_param_name_is_violation() {
        let rule = WwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "Basic re@alm=\"x\"")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("auth-param name"));
    }

    #[test]
    fn invalid_auth_param_value_token_is_violation() {
        let rule = WwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "Basic realm=abc@")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if let Some(vv) = v {
            assert!(
                vv.message.contains("auth-param value") || vv.message.contains("Invalid character")
            );
        } else {
            panic!("expected violation for invalid auth-param value token");
        }
    }

    #[test]
    fn auth_param_without_equals_reports_missing_value() {
        // This case is not representable as a single header field (top-level commas separate
        // challenges), but the per-challenge validation should detect a parameter without '='
        // when run against an assembled challenge string.
        let r = crate::helpers::auth::validate_challenge_syntax("Basic realm=\"x\", flag");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("missing value"));
    }

    #[test]
    fn auth_param_name_empty_is_violation() {
        let rule = WwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "Basic =\"x\"")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("auth-param name is empty"));
    }

    #[test]
    fn invalid_quoted_string_reports_message() {
        let rule = WwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "Basic realm=\"unfinished")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let vv = v.unwrap();
        assert!(
            vv.message.contains("Quoted-string") || vv.message.contains("Invalid quoted-string")
        );
    }

    #[test]
    fn quoted_string_with_extra_chars_reports_invalid() {
        let rule = WwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "Basic a=\"good\"extra")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let vv = v.unwrap();
        assert!(
            vv.message.contains("Invalid quoted-string") || vv.message.contains("Quoted-string")
        );
    }

    #[test]
    fn consecutive_commas_produce_empty_param_violation() {
        let rule = WwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "Basic realm=\"x\", , error=\"y\"")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if let Some(vv) = v {
            assert!(
                vv.message.contains("empty parameter") || vv.message.contains("empty challenge")
            );
        } else {
            panic!("expected violation for consecutive commas");
        }
    }

    #[test]
    fn challenge_missing_auth_scheme_is_violation() {
        let rule = WwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);
        // The leading space is `#challenge`'s `OWS`, so this is a parameter
        // with no challenge in front of it — which is what it was without the
        // space too. The two used to draw different messages.
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", " realm=\"x\"")],
        );
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
            .contains("parameter before any auth-scheme"));
    }

    #[test]
    fn empty_member_is_violation() {
        let rule = WwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", ",")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("empty"));
    }

    #[test]
    fn multiple_header_fields_checked() {
        let rule = WwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.append(
            "www-authenticate",
            hyper::header::HeaderValue::from_static("Basic realm=\"x\""),
        );
        hm.append(
            "www-authenticate",
            hyper::header::HeaderValue::from_static("NewScheme abc="),
        );
        tx.response.as_mut().unwrap().headers = hm;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn invalid_among_multiple_headers_reports_violation() {
        let rule = WwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);
        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.append(
            "www-authenticate",
            hyper::header::HeaderValue::from_static("error=\"x\""),
        );
        hm.append(
            "www-authenticate",
            hyper::header::HeaderValue::from_static("Basic realm=\"x\""),
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
    fn empty_auth_param_value_is_violation() {
        let rule = WwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "Basic realm=")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        if let Some(vv) = v {
            assert!(vv.message.contains("missing value"));
        }
    }

    #[test]
    fn quoted_string_with_escaped_quote_is_accepted() {
        let rule = WwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);
        // realm with escaped quote inside quoted-string
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "Basic realm=\"a\\\"b\"")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn realm_token_unquoted_is_accepted() {
        let rule = WwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "Basic realm=token123")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn token68_with_common_chars_is_accepted() {
        let rule = WwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "NewScheme abc+/.=-_123")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn first_part_invalid_but_rhs_is_quoted_reports_invalid_name() {
        let rule = WwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);
        // left side contains '/', RHS starts with '"' -> should be parsed as auth-param and reported
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "New abc/def=\"x\"")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("auth-param name"));
    }

    #[test]
    fn first_part_invalid_treated_as_token68_if_rhs_not_quoted() {
        let rule = WwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);
        // left contains invalid char '/', RHS does not start with '"' -> treat as token68
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "New abc/def=xyz")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn non_common_scheme_trailing_eq_accepted_as_token68() {
        let rule = WwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "NonCommon abc=")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn common_scheme_trailing_eq_reports_missing_value() {
        let rule = WwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "Basic abc=")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        if let Some(vv) = v {
            assert!(vv.message.contains("missing value"));
        }
    }

    #[test]
    fn suspicious_single_token_after_scheme_is_violation_for_non_token68() {
        let rule = WwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "NewScheme realm")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("suspicious single token"));
    }

    #[test]
    fn first_invalid_with_comma_parses_as_auth_param_and_reports_name() {
        let rule = WwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "New abc/def=\"x\", realm=\"y\"")],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("auth-param name"));
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "www_authenticate_challenge_syntax",
        ]);
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn message_and_id() {
        let rule = WwwAuthenticateChallengeSyntax;
        assert_eq!(rule.id(), "www_authenticate_challenge_syntax");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn scope_is_server() {
        let rule = WwwAuthenticateChallengeSyntax;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
