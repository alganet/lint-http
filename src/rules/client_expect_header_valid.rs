// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ClientExpectHeaderValid;

impl Rule for ClientExpectHeaderValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "client_expect_header_valid"
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
        // Only check request headers
        for hv in tx.request.headers.get_all("Expect").iter() {
            let s = match hv.to_str() {
                Ok(v) => v,
                Err(_) => continue,
            };

            for part in s.split(',') {
                let token = part.trim();
                if token.is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Empty element in Expect header".into(),
                    });
                }

                // Expectation = token [ "=" ( token / quoted-string ) ]
                // Delegate parsing/validation of a single list member to helper so it can
                // be tested independently of header validation. This helper implements a
                // simplified quoted-string parser that supports quoted-pair escapes ("\"").
                if let Some(msg) = validate_expect_member(token) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: msg,
                    });
                }
            }
        }

        None
    }
}

// Helper to validate a single Expect list-member string (trimmed). Returns Some(message)
// describing the violation when invalid, or None when valid.
pub(crate) fn validate_expect_member(member: &str) -> Option<String> {
    let token = member.trim();
    if token.is_empty() {
        return Some("Empty element in Expect header".into());
    }

    let mut iter = token.splitn(2, '=');
    let name = iter.next().unwrap().trim();
    if name.is_empty() {
        return Some("Empty expectation name in Expect header".into());
    }
    if let Some(c) = crate::token::find_invalid_token_char(name) {
        return Some(format!(
            "Invalid token in Expect header: '{}' (invalid char: '{}')",
            name, c
        ));
    }

    if let Some(rhs) = iter.next() {
        let rhs = rhs.trim();
        // RHS must not be empty when '=' is present
        if rhs.is_empty() {
            return Some("Empty expectation parameter in Expect header".into());
        }
        if rhs.starts_with('"') {
            // Parse quoted-string with support for quoted-pair escapes ("\\") per RFC 9110.
            // Ensure the quoted-string ends with an unescaped '"' and contains no unescaped
            // control characters (except HTAB). Quoted-pairs (backslash escapes) allow
            // the inclusion of otherwise-prohibited characters by escaping them.
            let mut prev_backslash = false;
            let mut terminated = false;
            // iterate over characters after the opening quote
            for c in rhs.chars().skip(1) {
                if prev_backslash {
                    prev_backslash = false;
                    continue;
                }
                if c == '\\' {
                    prev_backslash = true;
                    continue;
                }
                if c == '"' {
                    terminated = true;
                    break;
                }
                if c.is_ascii_control() && c != '\t' {
                    return Some(format!(
                        "Invalid control char in Expect header parameter: '{}'",
                        rhs
                    ));
                }
            }
            if !terminated {
                return Some(format!(
                    "Expect header quoted-string not terminated: '{}'",
                    rhs
                ));
            }
            // Ensure there's nothing after the terminating quote
            // Find index of terminating unescaped quote using bytes to get position
            let bytes = rhs.as_bytes();
            let mut i = 1usize; // skip opening quote
            let mut prev_backslash = false;
            while i < bytes.len() {
                let b = bytes[i];
                if prev_backslash {
                    prev_backslash = false;
                } else if b == b'\\' {
                    prev_backslash = true;
                } else if b == b'"' {
                    break;
                }
                i += 1;
            }
            if i >= bytes.len() || bytes[i] != b'"' {
                // Shouldn't happen because we checked 'terminated' above, but be defensive
                return Some(format!(
                    "Expect header quoted-string not terminated: '{}'",
                    rhs
                ));
            }
            if i + 1 != bytes.len() {
                return Some(format!(
                    "Invalid characters after quoted-string in Expect header parameter: '{}'",
                    rhs
                ));
            }
        } else if let Some(c) = crate::token::find_invalid_token_char(rhs) {
            return Some(format!(
                "Invalid token in Expect header parameter: '{}' (invalid char: '{}')",
                rhs, c
            ));
        }

        if name.eq_ignore_ascii_case("100-continue") {
            return Some("100-continue expectation must not have parameters".into());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    #[rstest]
    #[case("100-continue", false)]
    #[case("foo", false)]
    #[case("100-continue, foo", false)]
    #[case("a=b", false)]
    #[case("a=\"quoted\"", false)]
    #[case("", true)]
    #[case("a/b", true)]
    #[case("100-continue=param", true)]
    fn expect_header_cases(
        #[case] value: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ClientExpectHeaderValid;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        if value.is_empty() {
            hm.insert("Expect", HeaderValue::from_static(""));
        } else {
            // Some test cases intentionally include control or invalid UTF-8 bytes; if
            // HeaderValue::from_str fails, fall back to constructing from raw bytes to
            // exercise the to_str() Err branch used by production code.
            match HeaderValue::from_str(value) {
                Ok(hv) => hm.insert("Expect", hv),
                Err(_) => hm.insert(
                    "Expect",
                    HeaderValue::from_bytes(value.as_bytes()).expect("from_bytes should work"),
                ),
            };
        }
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        if expect_violation {
            assert!(v.is_some(), "case '{}' expected violation", value);
        } else {
            assert!(v.is_none(), "case '{}' expected no violation", value);
        }
        Ok(())
    }

    #[test]
    fn scope_is_client() -> anyhow::Result<()> {
        let rule = ClientExpectHeaderValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
        Ok(())
    }

    #[test]
    fn invalid_rhs_token_is_violation() -> anyhow::Result<()> {
        let rule = ClientExpectHeaderValid;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        hm.insert("Expect", HeaderValue::from_str("a=b/c")?);
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn non_utf8_expect_header_ignored() -> anyhow::Result<()> {
        let rule = ClientExpectHeaderValid;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        // Create a non-UTF8 header value to exercise the to_str() Err branch
        hm.insert(
            "Expect",
            HeaderValue::from_bytes(&[0xffu8]).expect("should construct non-utf8 header"),
        );
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn multiple_header_fields_validation_reports_invalid_member() -> anyhow::Result<()> {
        let rule = ClientExpectHeaderValid;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        hm.append("Expect", HeaderValue::from_static("100-continue"));
        hm.append("Expect", HeaderValue::from_static("a/b"));
        tx.request.headers = hm;

        // Should report a violation due to invalid 'a/b' token
        assert!(rule
            .check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config())
            .is_some());
        Ok(())
    }

    #[test]
    fn hundred_continue_case_insensitive_and_parameters_invalid() -> anyhow::Result<()> {
        let rule = ClientExpectHeaderValid;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        hm.insert("Expect", HeaderValue::from_static("100-Continue=param"));
        tx.request.headers = hm;

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn helper_detects_unterminated_quoted_string() {
        let msg = validate_expect_member("a=\"unterminated");
        assert!(matches!(msg, Some(ref s) if s.contains("not terminated")));
    }

    #[test]
    fn helper_detects_control_char_in_quoted_string() {
        let msg = validate_expect_member("a=\"bad\x01\"");
        assert!(matches!(msg, Some(ref s) if s.contains("Invalid control char")));
    }

    #[test]
    fn helper_detects_del_in_quoted_string() {
        // DEL (0x7f) is a control char and should be rejected
        let msg = validate_expect_member("a=\"bad\x7f\"");
        assert!(matches!(msg, Some(ref s) if s.contains("Invalid control char")));
    }

    #[test]
    fn helper_accepts_valid_quoted_string() {
        let msg = validate_expect_member("a=\"good\"");
        assert!(msg.is_none());
    }

    #[test]
    fn helper_accepts_htab_in_quoted_string() {
        // HTAB (\t) is allowed in qdtext per RFC 9110
        let msg = validate_expect_member("a=\"good\tvalue\"");
        assert!(msg.is_none());
    }

    #[test]
    fn helper_rejects_empty_name() {
        let msg = validate_expect_member("=value");
        assert!(matches!(msg, Some(ref s) if s.contains("Empty expectation name")));
    }

    #[test]
    fn helper_detects_escaped_quote_unterminated() {
        // Build a string that ends with an escaped quote, leaving the quoted-string unterminated
        let mut s = String::from("a=\"value");
        s.push('\\');
        s.push('"'); // now s is: a="value\"  (no terminating unescaped quote)
        let msg = validate_expect_member(&s);
        assert!(matches!(msg, Some(ref s) if s.contains("not terminated")));
    }

    #[test]
    fn helper_accepts_escaped_backslash_then_quote() {
        // Build: a="value\\"  where the backslash is escaped, then an unescaped terminating quote
        let mut s = String::from("a=\"value");
        s.push('\\');
        s.push('\\'); // two backslashes in the quoted-string
        s.push('"'); // terminating quote
        let msg = validate_expect_member(&s);
        assert!(msg.is_none());
    }

    #[test]
    fn helper_detects_trailing_chars_after_quoted_string() {
        let msg = validate_expect_member("a=\"good\"extra");
        assert!(matches!(msg, Some(ref s) if s.contains("Invalid characters after quoted-string")));
    }

    #[test]
    fn helper_rejects_empty_rhs() {
        let msg = validate_expect_member("a=");
        assert!(matches!(msg, Some(ref s) if s.contains("Empty expectation parameter")));

        let msg2 = validate_expect_member("a= ");
        assert!(matches!(msg2, Some(ref s) if s.contains("Empty expectation parameter")));
    }
}
