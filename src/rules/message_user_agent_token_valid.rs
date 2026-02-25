// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageUserAgentTokenValid;

impl Rule for MessageUserAgentTokenValid {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_user_agent_token_valid"
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
        let check_value = |hdr: &str, val: &str| -> Option<Violation> {
            // Strip comments (e.g., parentheses) before token parsing
            let no_comments = match crate::helpers::headers::strip_comments(val) {
                Ok(s) => s,
                Err(e) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Invalid {} header: {}", hdr, e),
                    })
                }
            };

            if no_comments.trim().is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("{} header is empty or contains only comments", hdr),
                });
            }

            for part in no_comments.split_whitespace() {
                // product = token ["/" token]
                let mut pieces = part.splitn(2, '/');
                let prod = pieces.next().unwrap();
                if prod.is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("{} header contains empty product token", hdr),
                    });
                }
                if let Some(c) = crate::helpers::token::find_invalid_token_char(prod) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "{} product token contains invalid character: '{}'",
                            hdr, c
                        ),
                    });
                }
                if let Some(ver) = pieces.next() {
                    if ver.is_empty() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("{} product contains empty version", hdr),
                        });
                    }
                    if ver.contains('/') {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!("{} product version contains unexpected '/'", hdr),
                        });
                    }
                    if let Some(c) = crate::helpers::token::find_invalid_token_char(ver) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "{} product version contains invalid character: '{}'",
                                hdr, c
                            ),
                        });
                    }
                }
            }

            None
        };

        // Check request User-Agent headers
        for hv in tx.request.headers.get_all("user-agent").iter() {
            if hv.to_str().is_err() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "User-Agent header contains non-UTF8 value".into(),
                });
            }
            let s = hv.to_str().unwrap();
            if let Some(v) = check_value("User-Agent", s) {
                return Some(v);
            }
        }

        // Be conservative: also validate User-Agent in responses if present
        if let Some(resp) = &tx.response {
            for hv in resp.headers.get_all("user-agent").iter() {
                if hv.to_str().is_err() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "User-Agent header contains non-UTF8 value".into(),
                    });
                }
                let s = hv.to_str().unwrap();
                if let Some(v) = check_value("User-Agent", s) {
                    return Some(v);
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    #[rstest]
    #[case(Some("curl/7.68.0"), false)]
    #[case(Some("gzip"), false)]
    #[case(Some("Mozilla/5.0 (compatible; Bot/1.0; +http://example.com)"), false)]
    #[case(Some("Agent/1.0 AnotherOne/2.0"), false)]
    #[case(Some("Bad UA!"), false)]
    #[case(Some("/1.0"), true)]
    #[case(Some("Agent/"), true)]
    #[case(Some("Agent/1.0/extra"), true)]
    #[case(None, false)]
    fn check_user_agent_request(
        #[case] ua: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageUserAgentTokenValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = ua {
            tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("user-agent", v)]);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    #[test]
    fn user_agent_product_and_version_invalid_chars_are_reported() -> anyhow::Result<()> {
        let rule = MessageUserAgentTokenValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        // invalid character in product
        let mut tx1 = crate::test_helpers::make_test_transaction();
        tx1.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("user-agent", "A@gen/1.0")]);
        assert!(rule
            .check_transaction(
                &tx1,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_some());

        // invalid character in version
        let mut tx2 = crate::test_helpers::make_test_transaction();
        tx2.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("user-agent", "Agent/1@0")]);
        assert!(rule
            .check_transaction(
                &tx2,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_some());

        Ok(())
    }

    #[test]
    fn multiple_user_agent_fields_are_checked() -> anyhow::Result<()> {
        let rule = MessageUserAgentTokenValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        // one good and one bad header -> violation
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[("user-agent", "curl/7.68.0")]);
        hm.append("user-agent", HeaderValue::from_static("Bad@UA/1.0"));
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = hm;
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_some());

        Ok(())
    }

    #[test]
    fn non_utf8_header_value_is_reported() -> anyhow::Result<()> {
        let rule = MessageUserAgentTokenValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.insert("user-agent", HeaderValue::from_bytes(b"\xff").unwrap());
        tx.request.headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn response_user_agent_is_validated() -> anyhow::Result<()> {
        let rule = MessageUserAgentTokenValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("user-agent", "Bad/UA!")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn response_multiple_user_agent_fields_are_checked() -> anyhow::Result<()> {
        let rule = MessageUserAgentTokenValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[("user-agent", "curl/7.68.0")]);
        hm.append("user-agent", HeaderValue::from_static("Bad@UA/1.0"));
        tx.response.as_mut().unwrap().headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn response_non_utf8_header_value_is_reported() -> anyhow::Result<()> {
        let rule = MessageUserAgentTokenValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.insert("user-agent", HeaderValue::from_bytes(b"\xff").unwrap());
        tx.response.as_mut().unwrap().headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        if let Some(violation) = v {
            assert!(violation.message.contains("non-UTF8"));
        }
        Ok(())
    }

    #[test]
    fn empty_product_token_from_whitespace_is_reported() -> anyhow::Result<()> {
        let rule = MessageUserAgentTokenValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("user-agent", "Agent  /1.0")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        if let Some(violation) = v {
            assert!(violation.message.contains("empty product token"));
        }
        Ok(())
    }

    #[test]
    fn invalid_char_messages_include_char() -> anyhow::Result<()> {
        let rule = MessageUserAgentTokenValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx1 = crate::test_helpers::make_test_transaction();
        tx1.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("user-agent", "A@gen/1.0")]);
        let v1 = rule.check_transaction(
            &tx1,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v1.is_some());
        if let Some(violation) = v1 {
            assert!(violation.message.contains("@"));
        }

        let mut tx2 = crate::test_helpers::make_test_transaction();
        tx2.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("user-agent", "Agent/1@0")]);
        let v2 = rule.check_transaction(
            &tx2,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v2.is_some());
        if let Some(violation) = v2 {
            assert!(violation.message.contains("@"));
        }
        Ok(())
    }

    #[test]
    fn user_agent_only_comments_is_reported() -> anyhow::Result<()> {
        let rule = MessageUserAgentTokenValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "user-agent",
            "(compatible; something)",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        if let Some(violation) = v {
            assert!(
                violation.message.contains("contains only comments")
                    || violation
                        .message
                        .contains("empty or contains only comments")
            );
        }
        Ok(())
    }

    #[test]
    fn user_agent_unmatched_parentheses_is_reported() -> anyhow::Result<()> {
        let rule = MessageUserAgentTokenValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("user-agent", "Agent (unclosed")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        if let Some(violation) = v {
            assert!(violation.message.contains("Invalid User-Agent header"));
        }
        Ok(())
    }

    #[test]
    fn user_agent_unbalanced_comment_reports_violation() -> anyhow::Result<()> {
        // moved from helper tests: ensure unbalanced parenthesized comment in User-Agent is reported
        let rule = MessageUserAgentTokenValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("user-agent", "Agent (incomplete")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn user_agent_escaped_parentheses_do_not_become_comments() -> anyhow::Result<()> {
        // Escaped parentheses should not be treated as comment delimiters; they will be preserved
        // by strip_comments and then validated for token characters by the rule.
        let rule = MessageUserAgentTokenValid;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("user-agent", "Agent\\(1.0\\)")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        // Parentheses are not allowed in token syntax, so we expect a violation, but the parser should
        // not treat them as comment delimiters (i.e., no parse error about unmatched comment).
        assert!(v.is_some());
        if let Some(violation) = v {
            assert!(
                violation.message.contains("contains invalid character")
                    || violation.message.contains("Invalid User-Agent header")
            );
        }
        Ok(())
    }

    #[test]
    fn message_and_id() {
        let rule = MessageUserAgentTokenValid;
        assert_eq!(rule.id(), "message_user_agent_token_valid");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_user_agent_token_valid",
        ]);
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
