// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageViaHeaderSyntaxValid;

impl Rule for MessageViaHeaderSyntaxValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_via_header_syntax_valid"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        use hyper::HeaderMap;

        // Helper to validate Via headers in a HeaderMap (reduces duplication)
        fn check_headers(hm: &HeaderMap, config: &crate::rules::RuleConfig) -> Option<Violation> {
            for (k, v) in hm.iter() {
                if k.as_str().eq_ignore_ascii_case("via") {
                    if let Ok(vv) = v.to_str() {
                        if let Some(err) = check_via_value(vv, config) {
                            return Some(err);
                        }
                    } else {
                        return Some(Violation {
                            rule: MessageViaHeaderSyntaxValid.id().into(),
                            severity: config.severity,
                            message: "Via header contains invalid (non-UTF8) value".into(),
                        });
                    }
                }
            }
            None
        }

        if let Some(err) = check_headers(&tx.request.headers, config) {
            return Some(err);
        }

        if let Some(resp) = &tx.response {
            if let Some(err) = check_headers(&resp.headers, config) {
                return Some(err);
            }
        }

        None
    }
}

// Split on commas that are not inside parentheses
fn split_commas_outside_parens(s: &str) -> Vec<&str> {
    let mut res = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' if depth > 0 => depth -= 1,
            ',' if depth == 0 => {
                res.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    res.push(s[start..].trim());
    res
}

fn is_valid_protocol(tok: &str) -> bool {
    if tok.is_empty() {
        return false;
    }
    // Allow token characters, slash and dot
    for c in tok.chars() {
        if c == '/' || c == '.' {
            continue;
        }
        if crate::helpers::token::is_tchar(c) {
            continue;
        }
        return false;
    }
    true
}

fn is_valid_received_by(rb: &str) -> bool {
    if rb.is_empty() {
        return false;
    }
    // IPv6 with bracket [::1] or [::1]:port
    if rb.starts_with('[') {
        match crate::helpers::ipv6::parse_bracketed_ipv6(rb) {
            Some((_inner, port_opt)) => {
                if let Some(port_str) = port_opt {
                    return crate::helpers::ipv6::parse_port_str(port_str).is_some();
                }
                return true;
            }
            None => return false,
        }
    }

    // Otherwise may be host[:port] or pseudonym (token)
    let parts: Vec<&str> = rb.splitn(2, ':').collect();
    let host = parts[0];
    if host.is_empty() {
        return false;
    }
    // host/pseudonym characters: allow tchar and '.' and ':' handled already
    if crate::helpers::token::find_invalid_token_char(host).is_some() {
        return false;
    }
    if parts.len() == 2 {
        let port = parts[1];
        if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
    }
    true
}

fn check_via_value(val: &str, config: &crate::rules::RuleConfig) -> Option<Violation> {
    let entries = split_commas_outside_parens(val);
    for e in entries {
        if e.is_empty() {
            return Some(Violation {
                rule: MessageViaHeaderSyntaxValid.id().into(),
                severity: config.severity,
                message: "Via header contains empty entry".into(),
            });
        }

        // Remove trailing comment if any
        let main = if let Some(pos) = e.find('(') {
            e[..pos].trim()
        } else {
            e
        };

        // split by whitespace
        let mut parts = main.split_whitespace();
        let proto = parts.next();
        let received_by = parts.next();

        if proto.is_none() || received_by.is_none() {
            return Some(Violation {
                rule: MessageViaHeaderSyntaxValid.id().into(),
                severity: config.severity,
                message: format!("Via entry '{}' missing protocol or received-by", e),
            });
        }

        let proto = proto.unwrap();
        if !is_valid_protocol(proto) {
            return Some(Violation {
                rule: MessageViaHeaderSyntaxValid.id().into(),
                severity: config.severity,
                message: format!("Via entry '{}' has invalid protocol token '{}'", e, proto),
            });
        }

        let rb = received_by.unwrap();

        // Any additional non-comment tokens after received-by are invalid
        if parts.next().is_some() {
            return Some(Violation {
                rule: MessageViaHeaderSyntaxValid.id().into(),
                severity: config.severity,
                message: format!("Via entry '{}' has unexpected extra tokens", e),
            });
        }

        if !is_valid_received_by(rb) {
            return Some(Violation {
                rule: MessageViaHeaderSyntaxValid.id().into(),
                severity: config.severity,
                message: format!("Via entry '{}' has invalid received-by '{}'", e, rb),
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("1.1 example.com", false)]
    #[case("HTTP/1.1 example.com", false)]
    #[case("1.1 example.com, 1.0 proxy", false)]
    #[case("1.1 example.com (cached)", false)]
    #[case("1.1 [::1]:8080", false)]
    #[case("HTTP/2.0 proxy:8080", false)]
    #[case("", true)]
    #[case(",", true)]
    #[case("1.1", true)]
    #[case("1.1 ", true)]
    #[case("1.1 example.com, , 1.0 proxy", true)]
    #[case("HT@P/1.1 example.com", true)]
    #[case("1.1 example.com:port", true)]
    #[case("1.1 :8080", true)]
    fn check_via_value_cases(
        #[case] val: &str,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let cfg = &crate::test_helpers::make_test_rule_config();
        let res = super::check_via_value(val, cfg);
        if expect_violation {
            assert!(res.is_some(), "expected violation for '{}', got none", val);
        } else {
            assert!(
                res.is_none(),
                "unexpected violation for '{}': {:?}",
                val,
                res
            );
        }
        Ok(())
    }

    #[test]
    fn check_request_header() -> anyhow::Result<()> {
        let rule = MessageViaHeaderSyntaxValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("via", "1.1 example.com")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn check_response_header_invalid() -> anyhow::Result<()> {
        let rule = MessageViaHeaderSyntaxValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[("via", "1.1")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn split_commas_inside_comment_is_ok() -> anyhow::Result<()> {
        let cfg = &crate::test_helpers::make_test_rule_config();
        let v = super::check_via_value("1.1 example.com (a,b,c), 1.0 proxy", cfg);
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn ipv6_missing_closing_bracket_is_invalid() -> anyhow::Result<()> {
        let cfg = &crate::test_helpers::make_test_rule_config();
        let v = super::check_via_value("1.1 [::1:8080", cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn ipv6_extra_after_bracket_is_invalid() -> anyhow::Result<()> {
        let cfg = &crate::test_helpers::make_test_rule_config();
        let v = super::check_via_value("1.1 [::1]extra", cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn non_utf8_header_value_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = MessageViaHeaderSyntaxValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        // create non-UTF8 header value
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("via", bad);
        tx.request.headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn invalid_host_with_space_is_violation() -> anyhow::Result<()> {
        let cfg = &crate::test_helpers::make_test_rule_config();
        let v = super::check_via_value("1.1 exa mple", cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn invalid_host_with_bad_char_is_violation() -> anyhow::Result<()> {
        let cfg = &crate::test_helpers::make_test_rule_config();
        let v = super::check_via_value("1.1 ex@host", cfg);
        assert!(v.is_some());
        Ok(())
    }

    #[rstest]
    #[case("", false)]
    #[case("1.1", true)]
    #[case("HTTP/2.0", true)]
    fn is_valid_protocol_cases(
        #[case] val: &str,
        #[case] expect_valid: bool,
    ) -> anyhow::Result<()> {
        assert_eq!(super::is_valid_protocol(val), expect_valid);
        Ok(())
    }

    #[rstest]
    #[case("", false)]
    #[case("[::1]", true)]
    #[case("[::1]:8080", true)]
    #[case("::1", false)]
    fn is_valid_received_by_cases(
        #[case] val: &str,
        #[case] expect_valid: bool,
    ) -> anyhow::Result<()> {
        assert_eq!(super::is_valid_received_by(val), expect_valid);
        Ok(())
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageViaHeaderSyntaxValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
