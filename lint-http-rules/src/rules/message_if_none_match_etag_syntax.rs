// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// `If-None-Match` header must be either `*` or a comma-separated list of entity-tags
/// (possibly weak `W/"..."`). Validates basic ETag grammar per RFC 9110 §7.6/§7.8.4.
pub struct MessageIfNoneMatchEtagSyntax;

impl Rule for MessageIfNoneMatchEtagSyntax {
    fn id(&self) -> &'static str {
        "message_if_none_match_etag_syntax"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        // Only applies to requests
        for hv in tx.request.headers.get_all("if-none-match").iter() {
            let s = match hv.to_str() {
                Ok(s) => s,
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "If-None-Match header contains non-UTF8 value".into(),
                    })
                }
            };

            let mut seen_any = false;
            for member in crate::helpers::headers::parse_list_header(s) {
                seen_any = true;
                if let Err(msg) = crate::helpers::headers::validate_entity_tag(member) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "If-None-Match header has invalid member '{}': {}",
                            member, msg
                        ),
                    });
                }
            }

            if !seen_any {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "If-None-Match header is empty or contains only whitespace".into(),
                });
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("If-None-Match ETag Syntax")
    }

    fn description(&self) -> &'static str {
        "`If-None-Match` headers must be either `*` or a comma-separated list of entity-tags. Entity-tags follow the grammar in RFC 9110 §7.6 and may be weak (prefix `W/`). This rule validates the basic syntax (quoting, escaping, and prohibition of control characters)."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("7.6"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6",
                note: "ETag header field",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("7.8.4"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8.4",
                note: "If-None-Match",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nIf-None-Match: \"abc123\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nIf-None-Match: W/\"weaktag\", \"strong\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nIf-None-Match: *",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nIf-None-Match: abc123   # missing quotes",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nIf-None-Match: W/abc    # missing quoted-string after W/",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nIf-None-Match: \"unterminated",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageIfNoneMatchEtagSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("*"), false)]
    #[case(Some("\"abc\""), false)]
    #[case(Some("W/\"abc\""), false)]
    #[case(Some("W/\"abc\", \"def\""), false)]
    #[case(Some("abc"), true)]
    #[case(Some("W/abc"), true)]
    #[case(Some("\"unterminated"), true)]
    #[case(None, false)]
    fn if_none_match_cases(#[case] header: Option<&str>, #[case] expect_violation: bool) {
        let rule = MessageIfNoneMatchEtagSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(hv) = header {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("if-none-match", hv)]);
        }

        let cfg = crate::test_helpers::make_test_config_with_severity(
            "message_if_none_match_etag_syntax",
            "warn",
        );

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
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
    }

    #[test]
    fn non_utf8_header_value_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = MessageIfNoneMatchEtagSyntax;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        hm.insert("if-none-match", bad);
        tx.request.headers = hm;

        let v = rule.check_transaction(
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
        crate::test_helpers::enable_rule(&mut cfg, "message_if_none_match_etag_syntax");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn empty_header_value_reports_violation() {
        let rule = MessageIfNoneMatchEtagSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("empty or contains only whitespace"));
    }

    #[test]
    fn comma_only_header_reports_violation() {
        let rule = MessageIfNoneMatchEtagSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", ",")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn multiple_header_fields_merged_and_valid() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = MessageIfNoneMatchEtagSyntax;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("if-none-match", HeaderValue::from_static("W/\"a\""));
        hm.append("if-none-match", HeaderValue::from_static("\"b\""));
        tx.request.headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn multiple_header_fields_one_invalid_reports_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = MessageIfNoneMatchEtagSyntax;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("if-none-match", HeaderValue::from_static("W/\"a\""));
        hm.append("if-none-match", HeaderValue::from_static("b"));
        tx.request.headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn id_and_scope_are_expected() {
        let r = MessageIfNoneMatchEtagSyntax;
        assert_eq!(r.id(), "message_if_none_match_etag_syntax");
        assert_eq!(r.scope(), crate::rules::RuleScope::Both);
    }
}
