// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::structured_fields::*;
use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessagePermissionsPolicyDirectivesValid;

impl Rule for MessagePermissionsPolicyDirectivesValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_permissions_policy_directives_valid"
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
        // Only inspect responses (server header)
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        for hv in resp.headers.get_all("permissions-policy").iter() {
            // Non-UTF8 value is a violation
            let s = match hv.to_str() {
                Ok(v) => v.trim(),
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Permissions-Policy header value is not valid UTF-8".into(),
                    })
                }
            };

            if s.is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Permissions-Policy header is empty".into(),
                });
            }

            if let Some(msg) = validate_permissions_policy(s) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("Invalid Permissions-Policy header: {}", msg),
                });
            }
        }

        None
    }
}

// Minimal validator focused on semantics required by the Permissions Policy spec:
// - top-level value must be a dictionary (comma-separated members)
// - each member must be FeatureIdentifier = MemberValue
// - feature identifier: 1*(ALPHA / DIGIT / "-")
// - MemberValue: token '*', token 'self', string, or inner-list '(...)'
// - MemberValue may have parameters after it; only parameter name 'report-to' is validated to be a quoted-string
// Conservative: relies on liberal parsing of inner-list contents; primary goal is to catch common mistakes
fn validate_permissions_policy(s: &str) -> Option<String> {
    // Reject control characters
    if s.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f) {
        return Some("contains control characters".into());
    }

    let members = split_commas_outside_quotes(s);
    for m in members {
        let m = m.trim();
        if m.is_empty() {
            return Some("empty directive/member".into());
        }

        // find '=' outside quotes
        let eq = find_char_outside_quotes(m, '=');
        if eq.is_none() {
            return Some(format!("member '{}' missing '=' and value", m));
        }
        let eq = eq.unwrap();
        let (left, right) = m.split_at(eq);
        let mut feature_part = left.trim();
        let value_part = right[1..].trim(); // drop '='

        // feature_part may contain params (e.g., key;param=1). Keep only the key name
        if let Some(semipos) = find_char_outside_quotes(feature_part, ';') {
            feature_part = feature_part[..semipos].trim();
        }

        if !is_valid_feature_identifier(feature_part) {
            return Some(format!("invalid feature identifier '{}'", feature_part));
        }

        // value_part may contain parameters separated by ';' outside quotes
        let parts = split_semicolons_outside_quotes(value_part);
        let item = parts.first().map(|s| s.trim()).unwrap_or("");
        if item.is_empty() {
            return Some(format!("member '{}' has empty value", feature_part));
        }

        // Disallow bare booleans, numbers, and byte-sequences as member values
        if item.starts_with('?') {
            return Some(format!(
                "member '{}' has boolean value not allowed",
                feature_part
            ));
        }
        if is_number(item) {
            return Some(format!(
                "member '{}' has numeric value not allowed",
                feature_part
            ));
        }
        if is_byte_sequence(item) {
            return Some(format!(
                "member '{}' has byte-sequence value not allowed",
                feature_part
            ));
        }

        // Allowed item forms: inner list '(...)', quoted-string '"..."', token '*' or 'self', or token-like
        if item.starts_with('(') {
            if !item.ends_with(')') {
                return Some(format!(
                    "member '{}' has unterminated inner-list",
                    feature_part
                ));
            }
            // inner-list contents are permissively accepted; ensure there are no empty members like '(,)'
            let inner = &item[1..item.len() - 1];
            if inner.trim() == "" {
                // empty inner list is acceptable: ()
            } else {
                // ensure no empty inner members after space-splitting outside quotes
                let members = split_spaces_outside_quotes(inner);
                for im in members {
                    if im.trim().is_empty() {
                        return Some(format!(
                            "member '{}' has empty inner-list member",
                            feature_part
                        ));
                    }
                }
            }
        } else if item.starts_with('"') {
            if !is_quoted_string(item) {
                return Some(format!(
                    "member '{}' has invalid quoted-string",
                    feature_part
                ));
            }
        } else if item.eq_ignore_ascii_case("*") || item.eq_ignore_ascii_case("self") {
            // allowed
        } else {
            // token-like; ensure token characters are tchars or allowed extras (':', '/', '.', '-', '_')
            if !is_valid_token_like(item) {
                return Some(format!(
                    "member '{}' has invalid token value '{}'",
                    feature_part, item
                ));
            }
        }

        // Validate parameters (if any): only 'report-to' is checked to be a quoted-string when present.
        for p in parts.iter().skip(1) {
            let p = p.trim();
            if p.is_empty() {
                return Some(format!("empty parameter for feature '{}'", feature_part));
            }
            if let Some(eqpos) = find_char_outside_quotes(p, '=') {
                let (pn, pv) = p.split_at(eqpos);
                let pn = pn.trim();
                let pv = pv[1..].trim();
                if pn.eq_ignore_ascii_case("report-to") {
                    if !is_quoted_string(pv) {
                        return Some(format!(
                            "parameter 'report-to' for '{}' must be a quoted-string",
                            feature_part
                        ));
                    }
                } else {
                    // other parameters are allowed but must at least be valid token or quoted-string
                    if !(is_valid_sf_key(pn)
                        && (is_valid_token_like(pv) || is_quoted_string(pv) || is_number(pv)))
                    {
                        return Some(format!(
                            "invalid parameter '{}' for feature '{}'",
                            pn, feature_part
                        ));
                    }
                }
            } else {
                // bare parameter name
                if !is_valid_sf_key(p) {
                    return Some(format!(
                        "invalid bare parameter '{}' for '{}'",
                        p, feature_part
                    ));
                }
            }
        }
    }
    None
}

// Shared parsing helpers (splitting, quoted-string, byte-seq, key/token-like)
// have been moved to `crate::helpers::structured_fields` and are imported at
// the top of this file. The feature-specific helpers remain here.

fn is_valid_feature_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("geolocation=(self \"https://example.com\")"), false)]
    #[case(Some("fullscreen=()"), false)]
    #[case(
        Some("payment=(\"https://pay.example\") ; report-to=\"endpoint\""),
        false
    )]
    #[case(Some("feature=*"), false)]
    #[case(Some("feature=self"), false)]
    #[case(Some("bad_feature_name=(self)"), true)]
    #[case(Some("geolocation"), true)]
    #[case(Some("geolocation=(self);report-to=endpoint"), true)]
    #[case(Some("geolocation=?1"), true)]
    #[case(Some(":byte:="), true)]
    #[case(None, false)]
    fn check_permissions_policy_cases(
        #[case] hdr: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = hdr {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("permissions-policy", v)]);
        }

        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(v.is_some(), "expected violation for {:?}: got none", hdr);
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for {:?}: got {:?}",
                hdr,
                v
            );
        }
        Ok(())
    }

    #[test]
    fn non_utf8_is_violation() -> anyhow::Result<()> {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "permissions-policy",
            hyper::header::HeaderValue::from_bytes(&[0xff])?,
        );
        tx.response.as_mut().unwrap().headers = hm;

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn message_and_id() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        assert_eq!(rule.id(), "message_permissions_policy_directives_valid");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_permissions_policy_directives_valid");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn control_characters_are_rejected() {
        // hyper rejects control characters in header values; test validator directly instead
        let res = validate_permissions_policy("geo=\u{0001}");
        assert!(res.is_some());
        assert!(res.unwrap().contains("control characters"));
    }

    #[test]
    fn empty_directive_is_reported() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            ",geolocation=(self)",
        )]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("empty directive"));
    }

    #[test]
    fn empty_value_is_reported() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("permissions-policy", "geolocation=")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("has empty value"));
    }

    #[test]
    fn numeric_values_are_rejected() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=1",
        )]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("numeric value"));
    }

    #[test]
    fn unterminated_inner_list_is_rejected() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self",
        )]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("unterminated inner-list"));
    }

    #[test]
    fn empty_inner_list_member_is_rejected() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self  )",
        )]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("empty inner-list"));
    }

    #[test]
    fn invalid_quoted_string_is_rejected() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=\"abc",
        )]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("invalid quoted-string"));
    }

    #[test]
    fn invalid_token_like_is_rejected() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=1abc",
        )]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("invalid token value"));
    }

    #[test]
    fn empty_parameter_is_rejected() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);",
        )]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("empty parameter"));
    }

    #[test]
    fn invalid_bare_parameter_is_rejected() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);123",
        )]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("invalid bare parameter"));
    }

    #[test]
    fn invalid_parameter_value_is_rejected() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);foo=!",
        )]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("invalid parameter 'foo'"));
    }

    #[test]
    fn report_to_quoted_is_ok() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);report-to=\"endpoint\"",
        )]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn feature_part_params_ignored() {
        // a semicolon before the '=' with its own '=' makes the member malformed and should be rejected
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation;meta=1=(self)",
        )]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn decimal_number_value_is_rejected() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=1.2",
        )]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("numeric value"));
    }

    #[test]
    fn byte_sequence_is_rejected() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=:YWJj:",
        )]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("byte-sequence"));
    }

    #[test]
    fn param_with_number_value_is_ok() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);foo=1",
        )]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn bare_param_is_ok() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);foo",
        )]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn param_with_quoted_value_is_ok() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);foo=\"bar\"",
        )]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn token_with_special_chars_is_ok() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=feat:sub/1.2-_",
        )]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn star_param_name_is_ok() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);*=1",
        )]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn invalid_param_name_uppercase_is_rejected() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);Foo=1",
        )]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("invalid parameter 'Foo'"));
    }

    #[test]
    fn feature_starting_with_digit_is_accepted() {
        // feature identifiers may start with a digit per our conservative validation
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("permissions-policy", "1geo=(self)")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn empty_header_value_is_violation() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("permissions-policy", "")]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("Permissions-Policy header is empty"));
    }

    #[test]
    fn param_name_with_dot_underscore_star_is_ok() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);a.b_c*=1",
        )]);

        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn quoted_string_with_control_char_is_rejected() {
        // hyper rejects control characters in header values; test validator directly instead
        let res = validate_permissions_policy("geolocation=\"a\u{0001}\"");
        assert!(res.is_some());
        // top-level control character check runs first
        assert!(res.unwrap().contains("control characters"));
    }
}
