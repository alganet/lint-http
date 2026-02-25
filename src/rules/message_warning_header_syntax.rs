// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Validate `Warning` header syntax per RFC 7234 §5.5:
/// warn = warn-value  ; we validate each warn-value in a (possibly comma-joined) header
/// warn-value = warn-code SP warn-agent SP warn-text [SP warn-date]
/// warn-code = 3DIGIT
/// warn-text = quoted-string
/// warn-date = DQUOTE HTTP-date DQUOTE
fn check_warning_value_str(val: &str) -> Option<String> {
    let parts = crate::helpers::headers::split_commas_respecting_quotes(val);
    for part in parts.iter() {
        let s = part.trim();
        if s.is_empty() {
            return Some("Warning header contains empty member".into());
        }

        // Need at least: 3-digit code, SP, agent, SP, quoted-string
        if s.len() < 5 {
            return Some("Warning member too short".into());
        }

        // Parse warn-code (first 3 chars should be digits)
        let code_chars: Vec<char> = s.chars().take(3).collect();
        if code_chars.len() < 3 || !code_chars.iter().all(|c| c.is_ascii_digit()) {
            return Some(format!(
                "Warning code must be 3 digits: '{}'",
                &s[..std::cmp::min(3, s.len())]
            ));
        }

        // after code there must be at least one space
        let mut idx = 3usize;
        if s.chars().nth(idx).map(|c| c != ' ').unwrap_or(true) {
            return Some("Missing space after warn-code".into());
        }
        // skip spaces
        while s.chars().nth(idx).map(|c| c == ' ').unwrap_or(false) {
            idx += 1;
            if idx >= s.len() {
                return Some("Warning member missing warn-agent and warn-text".into());
            }
        }

        // parse warn-agent (up to next space)
        let rest = &s[idx..];
        let mut agent_end = None;
        for (i, ch) in rest.char_indices() {
            if ch == ' ' {
                agent_end = Some(i);
                break;
            }
        }
        let agent = if let Some(i) = agent_end {
            &rest[..i]
        } else {
            rest
        };
        if agent.is_empty() {
            return Some("Warning agent is empty".into());
        }
        // agent must not contain control chars, DQUOTE, or whitespace
        if agent
            .chars()
            .any(|c| c.is_control() || c == '"' || c.is_whitespace())
        {
            return Some(format!(
                "Warning agent contains invalid character: '{}'",
                agent
            ));
        }

        // move index past agent
        idx += agent.len();
        // skip spaces
        while s.chars().nth(idx).map(|c| c == ' ').unwrap_or(false) {
            idx += 1;
            if idx >= s.len() {
                return Some("Warning member missing warn-text".into());
            }
        }

        // warn-text must be a quoted-string
        if s.chars().nth(idx) != Some('"') {
            return Some("Warning warn-text must be a quoted-string".into());
        }

        // find end of quoted-string (respecting backslash escapes)
        let bytes = s.as_bytes();
        let mut i = idx + 1;
        let mut prev_backslash = false;
        let mut found_end = None;
        while i < bytes.len() {
            let b = bytes[i];
            if prev_backslash {
                prev_backslash = false;
            } else if b == b'\\' {
                prev_backslash = true;
            } else if b == b'"' {
                found_end = Some(i);
                break;
            }
            i += 1;
        }
        if found_end.is_none() {
            return Some("Warning warn-text quoted-string not terminated".into());
        }
        let qend = found_end.unwrap();
        let qstr = &s[idx..=qend];
        if let Err(e) = crate::helpers::headers::validate_quoted_string(qstr) {
            return Some(format!("Invalid quoted-string in warn-text: {}", e));
        }

        // after the quoted-string there may be optional SP and a quoted warn-date
        let mut j = qend + 1;
        // skip spaces
        while j < s.len() && (s.as_bytes()[j] as char) == ' ' {
            j += 1;
        }
        if j < s.len() {
            // must be a quoted-string
            if s.as_bytes()[j] != b'"' {
                return Some("Warning warn-date must be a quoted-string if present".into());
            }
            // find end of date quoted-string
            let mut k = j + 1;
            let mut prev_bs = false;
            let mut end_date = None;
            while k < s.len() {
                let b = s.as_bytes()[k];
                if prev_bs {
                    prev_bs = false;
                } else if b == b'\\' {
                    prev_bs = true;
                } else if b == b'"' {
                    end_date = Some(k);
                    break;
                }
                k += 1;
            }
            if end_date.is_none() {
                return Some("Warning warn-date quoted-string not terminated".into());
            }
            let date_q = &s[j..=end_date.unwrap()];
            match crate::helpers::headers::unescape_quoted_string(date_q) {
                Ok(inner) => {
                    if !crate::http_date::is_valid_http_date(&inner) {
                        return Some(format!("Warn-date is not a valid HTTP-date: '{}'", inner));
                    }
                }
                Err(e) => return Some(format!("Invalid quoted-string in warn-date: {}", e)),
            }

            // ensure nothing else after date except whitespace
            let mut rem_idx = end_date.unwrap() + 1;
            while rem_idx < s.len() {
                if !(s.as_bytes()[rem_idx] as char).is_ascii_whitespace() {
                    return Some("Extra characters after warn-date".into());
                }
                rem_idx += 1;
            }
        }
    }
    None
}

pub struct MessageWarningHeaderSyntax;

impl Rule for MessageWarningHeaderSyntax {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_warning_header_syntax"
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
        // Check response headers
        if let Some(resp) = &tx.response {
            for hv in resp.headers.get_all("Warning").iter() {
                if let Ok(s) = hv.to_str() {
                    if let Some(msg) = check_warning_value_str(s) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("Invalid Warning header in response: {}", msg),
                        });
                    }
                } else {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "Warning header contains non-UTF8 value".into(),
                    });
                }
            }
        }

        // Check request headers as well (be conservative)
        for hv in tx.request.headers.get_all("Warning").iter() {
            if let Ok(s) = hv.to_str() {
                if let Some(msg) = check_warning_value_str(s) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Invalid Warning header in request: {}", msg),
                    });
                }
            } else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Warning header contains non-UTF8 value".into(),
                });
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
    #[case(Some("110 - \"Response is stale\""), false)]
    #[case(Some("214 example.com:80 \"Transformation applied\""), false)]
    #[case(
        Some("214 example.com:80 \"X\" \"Wed, 21 Oct 2015 07:28:00 GMT\""),
        false
    )]
    #[case(Some("214 example.com \"T\", 110 - \"Stale\""), false)]
    #[case(None, false)]
    #[case(Some(""), true)]
    #[case(Some(","), true)]
    #[case(Some("21a host \"text\""), true)]
    #[case(Some("214 host text"), true)]
    #[case(Some("214 host \"unclosed"), true)]
    #[case(Some("214 host \"t\" \"not-a-date\""), true)]
    fn check_warning_header_cases(#[case] header: Option<&str>, #[case] expect_violation: bool) {
        use crate::test_helpers::{make_test_transaction, make_test_transaction_with_response};
        let rule = MessageWarningHeaderSyntax;

        let tx = if let Some(h) = header {
            make_test_transaction_with_response(200, &[("Warning", h)])
        } else {
            make_test_transaction()
        };

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for header {:?}", header);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for header {:?}: {:?}",
                header,
                v.map(|x| x.message)
            );
        }
    }

    #[test]
    fn non_utf8_value_triggers_violation() {
        use crate::test_helpers::make_test_transaction_with_response;
        use hyper::header::HeaderValue;
        let rule = MessageWarningHeaderSyntax;
        let mut tx = make_test_transaction_with_response(200, &[]);
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .append("Warning", HeaderValue::from_bytes(&[0xff]).unwrap());
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-UTF8"));
    }

    #[test]
    fn request_header_valid_and_invalid_cases() {
        use crate::test_helpers::make_test_transaction;
        let rule = MessageWarningHeaderSyntax;

        // Valid request header -> no violation
        let mut tx = make_test_transaction();
        tx.request.headers.insert(
            "Warning",
            "214 example.com \"OK\""
                .parse::<hyper::header::HeaderValue>()
                .unwrap(),
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());

        // Missing space after code -> violation
        let mut tx2 = make_test_transaction();
        tx2.request.headers.insert(
            "Warning",
            "110-\"bad\"".parse::<hyper::header::HeaderValue>().unwrap(),
        );
        let v2 = rule.check_transaction(
            &tx2,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v2.is_some());
        assert!(v2
            .unwrap()
            .message
            .contains("Missing space after warn-code"));
    }

    #[rstest]
    #[case(
        "214 host \"x\" \"Wed, 21 Oct 2015 07:28:00 GMT\"garbage",
        Some("Extra characters after warn-date")
    )]
    #[case(
        "214 \"bad\" \"text\"",
        Some("Warning agent contains invalid character")
    )]
    #[case("214 host \"x\" extra", Some("warn-date must be a quoted-string"))]
    #[case("1", Some("Warning member too short"))]
    #[case(
        "214 host \"x\" \"Wed, 21 Oct 2015",
        Some("warn-date quoted-string not terminated")
    )]
    #[case(
        "214 host\tbad \"x\"",
        Some("Warning agent contains invalid character")
    )]
    #[case("214 host", Some("warn-text must be a quoted-string"))]
    #[case("214 ", None)]
    fn warn_date_and_agent_edge_cases_reported_param(
        #[case] header: &str,
        #[case] expect: Option<&str>,
    ) {
        use crate::test_helpers::make_test_transaction_with_response;
        let rule = MessageWarningHeaderSyntax;

        let tx = make_test_transaction_with_response(200, &[("Warning", header)]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        if let Some(expect_msg) = expect {
            assert!(v.unwrap().message.contains(expect_msg));
        }
    }

    #[test]
    fn empty_request_warning_reports_violation() {
        use crate::test_helpers::make_test_transaction;
        use hyper::header::HeaderValue;
        let mut tx = make_test_transaction();
        tx.request
            .headers
            .insert("Warning", HeaderValue::from_static(""));
        let rule = MessageWarningHeaderSyntax;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
    }

    #[test]
    fn multiple_members_empty_member_reports_violation() {
        use crate::test_helpers::make_test_transaction_with_response;
        let tx = make_test_transaction_with_response(
            200,
            &[("Warning", "214 host \"ok\", ,214 host \"bad\"")],
        );
        let rule = MessageWarningHeaderSyntax;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("empty member"));
    }
    #[test]
    fn warn_date_quoted_string_ends_with_escape_reports_error() {
        use crate::test_helpers::make_test_transaction_with_response;
        // date quoted-string ends with backslash before closing quote
        let tx = make_test_transaction_with_response(
            200,
            &[(
                "Warning",
                "214 host \"x\" \"Wed, 21 Oct 2015 07:28:00 GMT\\\"",
            )],
        );
        let rule = MessageWarningHeaderSyntax;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("warn-date quoted-string not terminated"));
    }
    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_warning_header_syntax",
        ]);
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageWarningHeaderSyntax;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn multiple_header_fields_all_valid_no_violation() {
        use crate::test_helpers::make_test_transaction_with_response;
        use hyper::header::HeaderValue;
        let rule = MessageWarningHeaderSyntax;

        // Two valid Warning header fields should not produce a violation
        let mut tx = make_test_transaction_with_response(200, &[("Warning", "214 host \"ok\"")]);
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .append("Warning", HeaderValue::from_static("110 - \"Stale\""));
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn response_missing_space_after_code_reports_violation() {
        use crate::test_helpers::make_test_transaction_with_response;
        let rule = MessageWarningHeaderSyntax;

        let tx = make_test_transaction_with_response(200, &[("Warning", "110-\"bad\"")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Missing space after warn-code"));
    }

    #[test]
    fn warn_text_ends_with_escape_reports_not_terminated() {
        use crate::test_helpers::make_test_transaction_with_response;
        use hyper::header::HeaderValue;
        let rule = MessageWarningHeaderSyntax;

        // warn-text quoted-string that ends with an escape before the closing quote (escaped quote)
        // leads to "not terminated" because the parser treats the escaped quote and doesn't find a
        // proper terminating quote.
        let mut tx = make_test_transaction_with_response(200, &[("Warning", "214 host \"ok\"")]);
        tx.response.as_mut().unwrap().headers.append(
            "Warning",
            HeaderValue::from_bytes(b"214 host \"abc\\\"").unwrap(),
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(
            msg.contains("warn-text quoted-string not terminated")
                || msg.contains("Invalid quoted-string in warn-text")
        );
    }

    #[rstest]
    #[case("214 host ", "Warning member missing warn-text")]
    #[case("214 host \"bad\u{0007}\"", "Invalid quoted-string in warn-text")]
    #[case(
        "214 host \"x\" \"Wed, 21 Oct 2015 07:28:00 \u{0007}GMT\"",
        "Invalid quoted-string in warn-date"
    )]
    fn check_warning_value_direct_cases(#[case] s: &str, #[case] expected_msg: &str) {
        let res = super::check_warning_value_str(s);
        assert!(res.is_some());
        let msg = res.unwrap();
        if s == "214 host " {
            // depending on parser path we may see either message
            assert!(
                msg.contains("Warning member missing warn-text")
                    || msg.contains("warn-text must be a quoted-string")
            );
        } else {
            assert!(msg.contains(expected_msg));
        }
    }

    // Direct tests for the parsing helper to cover some cases that are difficult to construct
    // via hyper HeaderValue (e.g., control characters in quoted-strings).
    #[test]
    fn check_warning_value_member_missing_warn_text_direct() {
        let s = "214 host ";
        let res = super::check_warning_value_str(s);
        assert!(res.is_some());
        // Accept either message variant depending on parser path
        let msg = res.unwrap();
        assert!(
            msg.contains("Warning member missing warn-text")
                || msg.contains("warn-text must be a quoted-string")
        );
    }

    #[test]
    fn check_warning_value_invalid_quoted_string_warn_text_direct() {
        // include a control char inside the quoted-string interior; HeaderValue forbids this but
        // calling the parser directly allows exercising validate_quoted_string errors.
        let s = "214 host \"bad\u{0007}\"";
        let res = super::check_warning_value_str(s);
        assert!(res.is_some());
        assert!(res.unwrap().contains("Invalid quoted-string in warn-text"));
    }

    #[test]
    fn check_warning_value_invalid_quoted_string_warn_date_direct() {
        // control char inside date quoted-string -> invalid quoted-string in warn-date
        let s = "214 host \"x\" \"Wed, 21 Oct 2015 07:28:00 \u{0007}GMT\"";
        let res = super::check_warning_value_str(s);
        assert!(res.is_some());
        assert!(res.unwrap().contains("Invalid quoted-string in warn-date"));
    }
}
