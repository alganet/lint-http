// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Validate `ETag` header values: must be a single entity-tag (strong or weak quoted-string)
/// per RFC 9110 §7.6 / §8.8.3. Also flags invalid UTF-8 and multiple header fields.
pub struct MessageEtagSyntax;

impl Rule for MessageEtagSyntax {
    fn id(&self) -> &'static str {
        "message_etag_syntax"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let Some(resp) = &tx.response else {
            return None;
        };

        let mut count = 0usize;
        for hv in resp.headers.get_all("etag").iter() {
            count += 1;
            let s = match hv.to_str() {
                Ok(s) => s,
                Err(_) => {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "ETag header value is not valid UTF-8".into(),
                    })
                }
            };

            let t = s.trim();
            // '*' is not a valid ETag in responses (used only in conditional match lists)
            if t == "*" {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message:
                        "ETag header value '*' is invalid for responses; ETag must be an entity-tag"
                            .into(),
                });
            }

            if let Err(msg) = crate::helpers::headers::validate_entity_tag(t) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!("ETag header invalid: {}", msg),
                });
            }
        }

        if count > 1 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Multiple ETag header fields present ({}); ETag must be a single entity-tag",
                    count
                ),
            });
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message ETag Syntax")
    }

    fn description(&self) -> &'static str {
        "Validate that the `ETag` response header contains a single, syntactically valid entity-tag (strong or weak) as defined by RFC 9110. This rule flags non-UTF-8 header values, the use of the special `*` value (which is only meaningful in conditional request headers), and the presence of multiple `ETag` header fields."
    }

    fn rfc_references(&self) -> &'static [&'static str] {
        &[
            "[RFC 9110 §7.6 — Entity Tag](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6)",
            "[RFC 9110 §8.8.3 — ETag header field](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3)",
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("(strong ETag)"),
                snippet: "HTTP/1.1 200 OK\nETag: \"33a64df551425fcc55e4d42a148795d9f25f89d4\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(weak ETag)"),
                snippet: "HTTP/1.1 200 OK\nETag: W/\"67ab43\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(`*` used in response)"),
                snippet: "HTTP/1.1 200 OK\nETag: *",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(missing quotes)"),
                snippet: "HTTP/1.1 200 OK\nETag: abc",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(multiple header fields)"),
                snippet: "HTTP/1.1 200 OK\nETag: \"a\"\nETag: \"b\"",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageEtagSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(Some("\"abc\""), false)]
    #[case(Some("W/\"abc\""), false)]
    #[case(Some("*"), true)]
    #[case(Some("abc"), true)]
    #[case(None, false)]
    fn etag_cases(#[case] value: Option<&str>, #[case] expect_violation: bool) {
        let rule = MessageEtagSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = value {
            tx.response = Some(crate::http_transaction::ResponseInfo {
                status: 200,
                version: "HTTP/1.1".into(),
                headers: crate::test_helpers::make_headers_from_pairs(&[("etag", v)]),

                body_length: None,
                trailers: None,
            });
        }

        let cfg = crate::test_helpers::make_test_config_with_severity(rule.id(), "warn");

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for value={:?}", value);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for value={:?}: {:?}",
                value,
                v
            );
        }
    }

    #[test]
    fn non_utf8_is_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = MessageEtagSyntax;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.insert("etag", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
            trailers: None,
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn multiple_etag_headers_reported() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = MessageEtagSyntax;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("etag", HeaderValue::from_static("\"a\""));
        hm.append("etag", HeaderValue::from_static("\"b\""));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
            trailers: None,
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_etag_syntax");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn id_and_scope_are_expected() {
        let r = MessageEtagSyntax;
        assert_eq!(r.id(), "message_etag_syntax");
        assert_eq!(r.scope(), crate::rules::RuleScope::Server);
    }
}
