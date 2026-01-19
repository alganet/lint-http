// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageWwwAuthenticateChallengeSyntax;

impl Rule for MessageWwwAuthenticateChallengeSyntax {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_www_authenticate_challenge_syntax"
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
        // Only check response headers; ignore non-UTF8 header values
        if let Some(resp) = &tx.response {
            for hv in resp.headers.get_all("www-authenticate").iter() {
                if let Ok(s) = hv.to_str() {
                    // Group members into assembled challenges using the helper so we can
                    // test the grouping logic independently and exercise more branches.
                    let challenges = match crate::helpers::auth::split_and_group_challenges(s) {
                        Ok(c) => c,
                        Err(msg) => {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: msg,
                            });
                        }
                    };

                    // Now validate each assembled challenge using helper to make it unit-testable
                    for challenge in challenges.iter() {
                        if let Err(msg) = crate::helpers::auth::validate_challenge_syntax(challenge)
                        {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: msg,
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
        let rule = MessageWwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_resp(val);
        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(v.is_some(), "val='{}' expected violation", val);
        } else {
            assert!(v.is_none(), "val='{}' expected no violation", val);
        }
    }

    #[test]
    fn non_utf8_header_values_are_ignored() {
        let rule = MessageWwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(401, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "www-authenticate",
            hyper::header::HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        tx.response.as_mut().unwrap().headers = hm;

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn parameter_before_scheme_is_violation() {
        let rule = MessageWwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "error=\"x\"")],
        );
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("parameter before any auth-scheme"));
    }

    #[test]
    fn trailing_empty_parameter_is_violation() {
        let rule = MessageWwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "Basic realm=\"x\", ")],
        );
        let v = rule.check_transaction(&tx, None, &cfg);
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
        let rule = MessageWwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "Basic realm=\"a\", NewScheme abcdef=")],
        );
        let v = rule.check_transaction(&tx, None, &cfg);
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
        let rule = MessageWwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "Basic re@alm=\"x\"")],
        );
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("auth-param name"));
    }

    #[test]
    fn invalid_auth_param_value_token_is_violation() {
        let rule = MessageWwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "Basic realm=abc@")],
        );
        let v = rule.check_transaction(&tx, None, &cfg);
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
        let rule = MessageWwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "Basic =\"x\"")],
        );
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("auth-param name is empty"));
    }

    #[test]
    fn invalid_quoted_string_reports_message() {
        let rule = MessageWwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "Basic realm=\"unfinished")],
        );
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let vv = v.unwrap();
        assert!(
            vv.message.contains("Quoted-string") || vv.message.contains("Invalid quoted-string")
        );
    }

    #[test]
    fn quoted_string_with_extra_chars_reports_invalid() {
        let rule = MessageWwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "Basic a=\"good\"extra")],
        );
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let vv = v.unwrap();
        assert!(
            vv.message.contains("Invalid quoted-string") || vv.message.contains("Quoted-string")
        );
    }

    #[test]
    fn consecutive_commas_produce_empty_param_violation() {
        let rule = MessageWwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "Basic realm=\"x\", , error=\"y\"")],
        );
        let v = rule.check_transaction(&tx, None, &cfg);
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
        let rule = MessageWwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();
        // member starts with whitespace -> missing scheme
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", " realm=\"x\"")],
        );
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("missing auth-scheme"));
    }

    #[test]
    fn empty_member_is_violation() {
        let rule = MessageWwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", ",")],
        );
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("empty"));
    }

    #[test]
    fn multiple_header_fields_checked() {
        let rule = MessageWwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();
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
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn invalid_among_multiple_headers_reports_violation() {
        let rule = MessageWwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();
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
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn empty_auth_param_value_is_violation() {
        let rule = MessageWwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "Basic realm=")],
        );
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        if let Some(vv) = v {
            assert!(vv.message.contains("missing value"));
        }
    }

    #[test]
    fn quoted_string_with_escaped_quote_is_accepted() {
        let rule = MessageWwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();
        // realm with escaped quote inside quoted-string
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "Basic realm=\"a\\\"b\"")],
        );
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn realm_token_unquoted_is_accepted() {
        let rule = MessageWwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "Basic realm=token123")],
        );
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn token68_with_common_chars_is_accepted() {
        let rule = MessageWwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "NewScheme abc+/.=-_123")],
        );
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn first_part_invalid_but_rhs_is_quoted_reports_invalid_name() {
        let rule = MessageWwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();
        // left side contains '/', RHS starts with '"' -> should be parsed as auth-param and reported
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "New abc/def=\"x\"")],
        );
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("auth-param name"));
    }

    #[test]
    fn first_part_invalid_treated_as_token68_if_rhs_not_quoted() {
        let rule = MessageWwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();
        // left contains invalid char '/', RHS does not start with '"' -> treat as token68
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "New abc/def=xyz")],
        );
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn non_common_scheme_trailing_eq_accepted_as_token68() {
        let rule = MessageWwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "NonCommon abc=")],
        );
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn common_scheme_trailing_eq_reports_missing_value() {
        let rule = MessageWwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "Basic abc=")],
        );
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        if let Some(vv) = v {
            assert!(vv.message.contains("missing value"));
        }
    }

    #[test]
    fn suspicious_single_token_after_scheme_is_violation_for_non_token68() {
        let rule = MessageWwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "NewScheme realm")],
        );
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("suspicious single token"));
    }

    #[test]
    fn first_invalid_with_comma_parses_as_auth_param_and_reports_name() {
        let rule = MessageWwwAuthenticateChallengeSyntax;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = crate::test_helpers::make_test_transaction_with_response(
            401,
            &[("www-authenticate", "New abc/def=\"x\", realm=\"y\"")],
        );
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("auth-param name"));
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_www_authenticate_challenge_syntax",
        ]);
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn message_and_id() {
        let rule = MessageWwwAuthenticateChallengeSyntax;
        assert_eq!(rule.id(), "message_www_authenticate_challenge_syntax");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn scope_is_server() {
        let rule = MessageWwwAuthenticateChallengeSyntax;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
