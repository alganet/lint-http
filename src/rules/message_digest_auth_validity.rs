// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageDigestAuthValidity;

impl Rule for MessageDigestAuthValidity {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_digest_auth_validity"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        for hv in tx.request.headers.get_all("authorization").iter() {
            match hv.to_str() {
                Ok(s) => {
                    let s = s.trim();
                    if s.is_empty() {
                        continue;
                    }
                    // Only care about Digest scheme
                    let mut parts = s.splitn(2, char::is_whitespace);
                    let scheme = parts.next().unwrap();
                    if !scheme.eq_ignore_ascii_case("digest") {
                        continue;
                    }
                    let rest = match parts.next() {
                        Some(r) => r.trim(),
                        None => {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: "Authorization Digest scheme missing parameters".into(),
                            })
                        }
                    };

                    // parse auth-param list into map
                    match crate::helpers::auth::parse_auth_params(rest) {
                        Ok(map) => {
                            // required fields per RFC 7616: username, realm, nonce, uri, response
                            let required = ["username", "realm", "nonce", "uri", "response"];
                            for &k in &required {
                                match map.get(k) {
                                    Some(v) => {
                                        // treat empty unquoted values or quoted-strings with empty inner content
                                        let is_empty = if v.is_empty() {
                                            true
                                        } else if v.starts_with('"') {
                                            // if quoted-string is syntactically invalid, default to 'false' so
                                            // it will be reported by the later quoted-string validation
                                            crate::helpers::headers::quoted_string_inner_trimmed_is_empty(v).unwrap_or_default()
                                        } else {
                                            false
                                        };

                                        if is_empty {
                                            return Some(Violation {
                                                rule: self.id().into(),
                                                severity: config.severity,
                                                message: format!(
                                                    "Digest Authorization missing or empty required parameter '{}'",
                                                    k
                                                ),
                                            })
                                        }
                                    }
                                    None => {
                                        return Some(Violation {
                                            rule: self.id().into(),
                                            severity: config.severity,
                                            message: format!(
                                                "Digest Authorization missing or empty required parameter '{}'",
                                                k
                                            ),
                                        })
                                    }
                                }
                            }
                            // validate tokensexp and quoted values basic syntax
                            for (k, v) in map.iter() {
                                // param names must be tokens
                                if let Some(inv) = crate::helpers::token::find_invalid_token_char(k)
                                {
                                    return Some(Violation {
                                        rule: self.id().into(),
                                        severity: config.severity,
                                        message: format!(
                                            "Invalid character '{}' in Digest auth-param name",
                                            inv
                                        ),
                                    });
                                }
                                // values may be quoted-string; if quoted, validate quoted-string
                                if v.starts_with('"') {
                                    if let Err(msg) =
                                        crate::helpers::headers::validate_quoted_string(v)
                                    {
                                        return Some(Violation {
                                            rule: self.id().into(),
                                            severity: config.severity,
                                            message: format!(
                                                "Invalid quoted-string in Digest auth-param '{}': {}",
                                                k, msg
                                            ),
                                        });
                                    }
                                } else {
                                    // Unquoted values: 'uri' may contain '/' and other URI characters,
                                    // allow it if it doesn't contain control characters.
                                    if k.eq_ignore_ascii_case("uri") {
                                        if v.chars().any(|c| (c as u32) < 0x20 || c == '\x7f') {
                                            return Some(Violation {
                                                rule: self.id().into(),
                                                severity: config.severity,
                                                message: format!(
                                                    "Digest auth-param '{}' contains control characters",
                                                    k
                                                ),
                                            });
                                        }
                                    } else {
                                        // For other params, require token-like values
                                        if let Some(inv) =
                                            crate::helpers::token::find_invalid_token_char(v)
                                        {
                                            return Some(Violation {
                                                rule: self.id().into(),
                                                severity: config.severity,
                                                message: format!(
                                                    "Invalid character '{}' in Digest auth-param value for '{}'",
                                                    inv, k
                                                ),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                        Err(msg) => {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!("Invalid Digest auth parameters: {}", msg),
                            })
                        }
                    }
                }
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Authorization header contains non-UTF8 value".into(),
                    })
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

    #[rstest]
    #[case(
        Some("Digest username=Mufasa, realm=test, nonce=abc, uri=/, response=d"),
        false
    )]
    #[case(
        Some("Digest username=Mufasa, realm=test, nonce=abc, uri=/, response=d, algorithm=MD5"),
        false
    )]
    #[case(Some("Digest username=Mufasa, realm=test, nonce=abc, uri=/"), true)]
    #[case(
        Some("Digest username=, realm=test, nonce=abc, uri=/, response=d"),
        true
    )]
    #[case(
        Some("Digest username=Mufasa, realm=test, nonce=a@bad, uri=/, response=d"),
        true
    )]
    #[case(Some("Basic abc"), false)]
    #[case(Some("Digest"), true)]
    #[case(
        Some("Digest username=\"Mufasa, realm=test, nonce=abc, uri=/, response=d"),
        true
    )]
    #[case(None, false)]
    fn check_digest_authorization(
        #[case] header: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(h) = header {
            tx.request
                .headers
                .append("authorization", h.parse().unwrap());
        }

        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn invalid_param_name_reports_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "Digest user@name=abc, realm=test, nonce=abc, uri=/, response=d"
                .parse()
                .unwrap(),
        );

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(v.message.contains("Invalid character"));
        Ok(())
    }

    #[test]
    fn lowercase_scheme_is_accepted() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "digest username=Mufasa, realm=test, nonce=abc, uri=/, response=d"
                .parse()
                .unwrap(),
        );

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn parse_params_missing_value_reports_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "Digest username, realm=test, nonce=abc, uri=/, response=d"
                .parse()
                .unwrap(),
        );

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(v.message.contains("Invalid Digest auth parameters"));
        Ok(())
    }

    #[test]
    fn non_utf8_header_reports_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            hyper::header::HeaderValue::from_bytes(b"Digest \xff").unwrap(),
        );
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn required_param_quoted_empty_reports_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "Digest username=\"\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\""
                .parse()
                .unwrap(),
        );

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(
            v.message.contains("missing or empty required parameter")
                || v.message.contains("Invalid Digest auth parameters")
        );
        Ok(())
    }

    #[test]
    fn quoted_string_with_escaped_quote_is_accepted() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        // username contains an escaped quote inside the quoted-string which is valid
        tx.request.headers.append(
            "authorization",
            "Digest username=\"Mu\\\"fasa\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\"".parse().unwrap(),
        );

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn invalid_quoted_string_reports_specific_message() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        // username quoted-string missing closing quote should trigger quoted-string validation error
        tx.request.headers.append(
            "authorization",
            "Digest username=\"Mufasa, realm=test, nonce=abc, uri=/, response=d"
                .parse()
                .unwrap(),
        );

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(
            msg.contains("Invalid quoted-string")
                || msg.contains("Invalid Digest auth parameters")
                || msg.contains("missing or empty required parameter")
        );
        Ok(())
    }

    #[test]
    fn header_value_construction_rejects_control_chars() -> anyhow::Result<()> {
        // Hyper's HeaderValue validation rejects control characters in header values (as per the HTTP
        // specification). Therefore it's not possible to construct a header containing LF/CR to feed
        // through the normal header pipeline; the constructor will return an error. Assert that
        // behavior here so we don't rely on impossible-to-construct inputs.
        use hyper::header::HeaderValue;
        let raw = b"Digest username=Mufasa, realm=test, nonce=abc, uri=/bad\n, response=d";
        let hv = HeaderValue::from_bytes(raw);
        assert!(hv.is_err());
        Ok(())
    }

    #[test]
    fn digest_scheme_with_whitespace_but_no_params_reports_invalid_params() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request
            .headers
            .append("authorization", "Digest    ".parse().unwrap());

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let v = v.unwrap();
        // message should be non-empty and indicate a problem with parameters
        assert!(!v.message.is_empty());
        Ok(())
    }

    #[test]
    fn digest_scheme_without_params_reports_missing_parameters_message() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request
            .headers
            .append("authorization", "Digest".parse().unwrap());

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(v.message.contains("missing parameters"));
        Ok(())
    }

    #[test]
    fn invalid_response_value_token_char_reports_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "Digest username=Mufasa, realm=test, nonce=abc, uri=/, response=ab@d"
                .parse()
                .unwrap(),
        );

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(
            msg.contains("Invalid character") || msg.contains("Invalid Digest auth parameters")
        );
        Ok(())
    }

    #[test]
    fn invalid_quoted_string_extra_chars_reports_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        // username quoted-string followed by extra chars should trigger quoted-string validation error
        tx.request.headers.append(
            "authorization",
            "Digest username=\"Mufasa\"x, realm=test, nonce=abc, uri=/, response=d"
                .parse()
                .unwrap(),
        );

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(
            msg.contains("Invalid quoted-string") || msg.contains("Invalid Digest auth parameters")
        );
        Ok(())
    }

    #[test]
    fn duplicate_param_last_empty_reports_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        // username appears twice; last one is empty -> should trigger missing/empty required param
        tx.request.headers.append(
            "authorization",
            "Digest username=Mufasa, username=, realm=test, nonce=abc, uri=/, response=d"
                .parse()
                .unwrap(),
        );

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(
            v.message.contains("missing or empty required parameter")
                || v.message.contains("Invalid Digest auth parameters")
        );
        Ok(())
    }

    #[test]
    fn multiple_authorization_headers_one_invalid_triggers_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        // add a Basic header first, then an invalid Digest (empty response)
        tx.request
            .headers
            .append("authorization", "Basic abc".parse().unwrap());
        tx.request.headers.append(
            "authorization",
            "Digest username=Mufasa, realm=test, nonce=abc, uri=/, response="
                .parse()
                .unwrap(),
        );

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(
            v.message.contains("missing or empty required parameter")
                || v.message.contains("Invalid Digest auth parameters")
        );
        Ok(())
    }

    #[test]
    fn multiple_digest_headers_one_invalid_after_valid_triggers_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        // first a valid Digest, then an invalid Digest (empty response)
        tx.request.headers.append(
            "authorization",
            "Digest username=Alice, realm=test, nonce=abc, uri=/, response=resp1"
                .parse()
                .unwrap(),
        );
        tx.request.headers.append(
            "authorization",
            "Digest username=Bob, realm=test, nonce=abc, uri=/, response="
                .parse()
                .unwrap(),
        );

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn multiple_digest_headers_all_valid_no_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "Digest username=Alice, realm=test, nonce=abc, uri=/, response=resp1"
                .parse()
                .unwrap(),
        );
        tx.request.headers.append(
            "authorization",
            "Digest username=Bob, realm=test, nonce=def, uri=/, response=resp2"
                .parse()
                .unwrap(),
        );

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn empty_authorization_header_ignored() {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        // An empty Authorization value should be ignored
        tx.request
            .headers
            .append("authorization", "".parse().unwrap());
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn unquoted_username_with_space_reports_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "Digest username=Mu fasa, realm=test, nonce=abc, uri=/, response=d"
                .parse()
                .unwrap(),
        );

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn quoted_string_ends_with_escape_reports_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "Digest username=\"Mu\\\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\""
                .parse()
                .unwrap(),
        );
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(
            msg.contains("Invalid quoted-string")
                || msg.contains("Invalid Digest auth parameters")
                || msg.contains("missing or empty required parameter")
        );
        Ok(())
    }

    #[test]
    fn required_param_unquoted_empty_reports_violation() -> anyhow::Result<()> {
        let rule = MessageDigestAuthValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "Digest username=, realm=test, nonce=abc, uri=/, response=d"
                .parse()
                .unwrap(),
        );
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(
            msg.contains("missing or empty required parameter")
                || msg.contains("Invalid Digest auth parameters")
        );
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_digest_auth_validity");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn scope_is_client() {
        let rule = MessageDigestAuthValidity;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }
}
