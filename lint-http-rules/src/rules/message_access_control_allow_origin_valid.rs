// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageAccessControlAllowOriginValid;

impl Rule for MessageAccessControlAllowOriginValid {
    fn id(&self) -> &'static str {
        "message_access_control_allow_origin_valid"
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
        let resp = tx.response.as_ref()?;

        let headers = &resp.headers;

        let acao_count = headers
            .get_all("access-control-allow-origin")
            .iter()
            .count();
        if acao_count == 0 {
            return None;
        }

        // Multiple header fields are not allowed for Access-Control-Allow-Origin: the
        // header carries one value — an echoed origin, `null`, or `*` — not a list.
        // cite(Fetch): "Indicates whether the response can be shared, via returning the literal value of the `Origin` request header (which can be `null`) or `*` in a response."
        if acao_count > 1 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Multiple Access-Control-Allow-Origin header fields present; only a single value ('*' or a single origin) is allowed".into(),
            });
        }

        // There is a single header field; validate its single value semantics and origin syntax.
        let hv = headers
            .get_all("access-control-allow-origin")
            .iter()
            .next()
            .unwrap();
        let s = match hv.to_str() {
            Ok(v) => v.trim(),
            Err(_) => return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message:
                    "Access-Control-Allow-Origin header contains non-ASCII or control characters"
                        .into(),
            }),
        };

        // Must be a single value (not a comma-separated list)
        let members: Vec<String> = crate::helpers::headers::list_members(s)
            .map(|m| m.to_string())
            .collect();
        if members.len() != 1 {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Access-Control-Allow-Origin must be a single value ('*', 'null', or a serialized origin)".into(),
            });
        }

        let member = members.into_iter().next().unwrap();
        if member == "*" || member == "null" {
            return None;
        }

        if !crate::helpers::headers::is_valid_serialized_origin(&member) {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Access-Control-Allow-Origin contains invalid origin: '{}'",
                    member
                ),
            });
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Access-Control-Allow-Origin Syntax")
    }

    fn description(&self) -> &'static str {
        "This rule checks that the `Access-Control-Allow-Origin` response header is syntactically valid: it must be a single value and that value must be either `*`, `null`, or a valid serialized-origin (scheme://host[:port]). Multiple header fields or comma-separated lists are not allowed per the CORS semantics and will be flagged as violations."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "MDN Access-Control-Allow-Origin",
                section: None,
                url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin",
                note: "Access-Control-Allow-Origin",
            },
            crate::rules::SpecRef {
                spec: "Fetch",
                section: Some("3.3.3"),
                url: "https://fetch.spec.whatwg.org/#http-access-control-allow-origin",
                note: "`Access-Control-Allow-Origin` carries one value: an echoed origin, `null`, or `*`",
            },
            crate::rules::SpecRef {
                spec: "Fetch",
                section: Some("3.2"),
                url: "https://fetch.spec.whatwg.org/#origin-header",
                note: "Governing origin syntax: `serialized-origin` ends at its authority, so a path (not even a trailing slash), a query or a fragment all disqualify it; the host inside it is a `reg-name` or a bracketed `IP-literal`, so a character outside those productions or a malformed percent-encoding disqualifies it too; and `origin-or-null`'s `null` is case-sensitive",
            },
            crate::rules::SpecRef {
                spec: "RFC 6454",
                section: Some("7.1"),
                url: "https://www.rfc-editor.org/rfc/rfc6454.html#section-7.1",
                note: "Historical origin syntax the non-`*` value is validated against — `serialized-origin = scheme \"://\" host [ \":\" port ]`, and `null` via origin-list-or-null; Fetch §3.2 supplants it",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: null",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://a, https://b",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://a\nAccess-Control-Allow-Origin: https://b",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("a serialized origin has no path, not even a trailing slash"),
                snippet: "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://example.com/",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageAccessControlAllowOriginValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    use crate::test_helpers::make_test_transaction;

    #[test]
    fn no_response_no_violation() {
        let rule = MessageAccessControlAllowOriginValid;
        let tx = make_test_transaction();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn response_without_acao_header_returns_none() {
        let rule = MessageAccessControlAllowOriginValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "text/plain")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[rstest]
    #[case("*")]
    #[case("null")]
    #[case("https://example.com")]
    #[case("  https://example.com  ")]
    // A port is a 16-bit unsigned integer and `0` is one of them — reserved at
    // the edge of a range rather than invalid. The shared origin reader rejected
    // it until the port reading was shared with the two rules that had audited
    // the bound, so this value drew a finding naming an origin that is one.
    #[case("https://example.com:0")]
    #[case("https://example.com:65535")]
    fn valid_single_values(#[case] val: &str) {
        let rule = MessageAccessControlAllowOriginValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("access-control-allow-origin", val)],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(
            v.is_none(),
            "expected no violation for '{}': got {:?}",
            val,
            v
        );
    }

    // § 3.2 terminates an authority at "/", "?" or "#", and a serialized origin
    // ends where its authority does. Only the first of the three reached this
    // rule until the shared validator stopped enumerating them by hand.
    #[rstest]
    #[case("https://example.com/")]
    #[case("https://example.com/path")]
    #[case("https://example.com?x=1")]
    #[case("https://example.com#frag")]
    // The authority's *contents*, which the check measured nothing of: none of
    // these characters is in any `reg-name`, and a `%zz` is no `pct-encoded`.
    #[case("https://exa|mple.com")]
    #[case("https://a<b>c")]
    #[case("https://a^b")]
    #[case("https://a%zzb")]
    #[case("https://[foo]")]
    fn origin_with_anything_after_the_authority_is_violation(#[case] val: &str) {
        let rule = MessageAccessControlAllowOriginValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("access-control-allow-origin", val)],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let v = v.unwrap_or_else(|| panic!("expected violation for '{}'", val));
        assert!(v.message.contains("invalid origin"));
    }

    #[test]
    fn uppercase_null_is_violation() {
        let rule = MessageAccessControlAllowOriginValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("access-control-allow-origin", "NULL")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("invalid origin"));
    }

    #[test]
    fn comma_separated_values_are_violation() {
        let rule = MessageAccessControlAllowOriginValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("access-control-allow-origin", "https://a, https://b")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("single value"));
    }

    #[test]
    fn multiple_header_fields_are_violation() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = MessageAccessControlAllowOriginValid;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("access-control-allow-origin", "https://a")]);
        hdrs.append(
            "access-control-allow-origin",
            HeaderValue::from_static("https://b"),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,

            body_length: None,
            trailers: None,
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Multiple"));
    }

    #[test]
    fn invalid_origin_is_violation() {
        let rule = MessageAccessControlAllowOriginValid;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("access-control-allow-origin", "example.com")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("invalid origin"));
    }

    #[test]
    fn non_utf8_header_is_violation() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = MessageAccessControlAllowOriginValid;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("access-control-allow-origin", "https://a")]);
        hdrs.insert(
            "access-control-allow-origin",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hdrs,

            body_length: None,
            trailers: None,
        });

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-ASCII"));
    }

    #[test]
    fn scope_is_server() {
        let rule = MessageAccessControlAllowOriginValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = MessageAccessControlAllowOriginValid;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("error".into()));
        cfg.rules.insert(
            "message_access_control_allow_origin_valid".into(),
            toml::Value::Table(table),
        );

        // validate should succeed without error
        rule.validate(&cfg)?;
        Ok(())
    }
}
