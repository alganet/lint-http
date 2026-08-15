// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageTimingAllowOriginValidity;

impl Rule for MessageTimingAllowOriginValidity {
    fn id(&self) -> &'static str {
        "message_timing_allow_origin_validity"
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
        // The header is server-sent: it rides responses, so only the response side is
        // inspected.
        // cite(Resource Timing): "Server-side applications may return the Timing-Allow-Origin HTTP response header to allow the User Agent to fully expose, to the document origin(s) specified, the values of attributes that would have been zero due to those cross-origin restrictions."
        let resp = tx.response.as_ref()?;

        let headers = &resp.headers;

        let tao_count = headers.get_all("timing-allow-origin").iter().count();
        if tao_count == 0 {
            return None;
        }

        // Combine members across multiple header fields; list_members handles commas & whitespace.
        // Several header fields are explicitly allowed, so this rule checks the members,
        // not the field count — unlike Access-Control-Allow-Origin, which carries one value.
        // cite(Resource Timing): "The sender MAY generate multiple Timing-Allow-Origin header fields."
        // cite(Resource Timing): "The recipient MAY combine multiple Timing-Allow-Origin header fields by appending each subsequent field value to the combined field value in order, separated by a comma."
        for hv in headers.get_all("timing-allow-origin").iter() {
            // cite(RFC 9110 § 5.5): "newly defined fields SHOULD limit their values to visible US-ASCII octets (VCHAR), SP, and HTAB"
            let s =
                match hv.to_str() {
                    Ok(v) => v,
                    Err(_) => return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message:
                            "Timing-Allow-Origin header contains non-ASCII or control characters"
                                .into(),
                    }),
                };

            // Empty header value (only whitespace) is invalid: `1#` requires at least
            // one member.
            // cite(Resource Timing): "Timing-Allow-Origin = 1#( origin-or-null / wildcard )"
            if s.trim().is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Timing-Allow-Origin header value is empty".into(),
                });
            }

            // Detect empty list members caused by consecutive commas or leading empty
            // members. The header's ABNF uses RFC 9110's list construct, so its
            // empty-element rules apply.
            // cite(Resource Timing): "The header’s value is represented by the following ABNF [RFC5234] (using List Extension, [RFC9110]):"
            let parts: Vec<&str> = s.split(',').collect();
            for (i, raw_member) in parts.iter().enumerate() {
                if raw_member.trim().is_empty() {
                    // An internal/leading empty member means the sender generated an
                    // empty list element.
                    // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
                    if parts.iter().skip(i + 1).any(|p| !p.trim().is_empty()) {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Timing-Allow-Origin header contains empty member".into(),
                        });
                    }
                    // Otherwise it's trailing empty member(s) (e.g., "https://a, ");
                    // tolerated as recipient-side leniency.
                    // cite(RFC 9110 § 5.6.1.2): "A recipient MUST parse and ignore a reasonable number of empty list elements: enough to handle common mistakes by senders that merge values, but not so much that they could be used as a denial-of-service mechanism"
                }
            }
            for m in crate::helpers::headers::list_members(s) {
                // `wildcard` and the case-sensitive lowercase `null` are the two
                // non-origin members the grammar admits (both productions resolve
                // into Fetch).
                // cite(Fetch): "origin-or-null = serialized-origin / %s"null" ; case-sensitive"
                if m == "*" || m == "null" {
                    continue;
                }

                // Anything else must be a serialized origin; the helper owns the
                // grammar it is validated against.
                if !crate::helpers::headers::is_valid_serialized_origin(m) {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!("Timing-Allow-Origin contains invalid origin: '{}'", m),
                    });
                }
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Message Timing-Allow-Origin Header Validity")
    }

    fn description(&self) -> &'static str {
        "Validate the `Timing-Allow-Origin` response header values. The header's value\nmust be `*` (wildcard), the lowercase literal `null` (the grammar's `%s\"null\"`\nis case-sensitive), or one or more serialized origins (`scheme://host[:port]`).\nMultiple header fields are allowed and their values are combined using HTTP\nlist semantics. This rule detects header values that cannot be decoded as\nvisible US-ASCII, an entirely empty header value, and invalid origin\nserializations."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "Resource Timing",
                section: Some("3.5.2"),
                url: "https://www.w3.org/TR/resource-timing/#sec-timing-allow-origin",
                note: "`Timing-Allow-Origin` response header and its ABNF",
            },
            crate::rules::SpecRef {
                spec: "Fetch",
                section: Some("3.2"),
                url: "https://fetch.spec.whatwg.org/#origin-header",
                note: "`origin-or-null` and `serialized-origin`, the productions the grammar's members resolve to (`null` is case-sensitive)",
            },
            crate::rules::SpecRef {
                spec: "RFC 6454",
                section: Some("7.1"),
                url: "https://www.rfc-editor.org/rfc/rfc6454.html#section-7.1",
                note: "Historical serialized-origin shape (`scheme \"://\" host [ \":\" port ]`) the conservative validator implements; Fetch supplants the serialization",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nTiming-Allow-Origin: *",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nTiming-Allow-Origin: https://example.com",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nTiming-Allow-Origin: https://a, https://b",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nTiming-Allow-Origin: https:///foo",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("`null` is case-sensitive"),
                snippet: "HTTP/1.1 200 OK\nTiming-Allow-Origin: NULL",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nTiming-Allow-Origin: ",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nTiming-Allow-Origin: \t",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageTimingAllowOriginValidity;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    use crate::test_helpers::make_test_transaction;

    #[test]
    fn no_response_no_violation() {
        let rule = MessageTimingAllowOriginValidity;
        let tx = make_test_transaction();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn response_without_header_returns_none() {
        let rule = MessageTimingAllowOriginValidity;
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
    #[case("https://a, https://b")]
    fn valid_values(#[case] val: &str) {
        let rule = MessageTimingAllowOriginValidity;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("timing-allow-origin", val)],
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

    #[test]
    fn non_utf8_header_is_violation() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = MessageTimingAllowOriginValidity;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("timing-allow-origin", "https://a")]);
        hdrs.insert(
            "timing-allow-origin",
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
    fn trailing_comma_is_allowed() {
        // Helper parsing ignores empty members (trailing commas are tolerated); no violation expected
        let rule = MessageTimingAllowOriginValidity;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("timing-allow-origin", "https://a,  ")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(
            v.is_none(),
            "expected no violation for trailing comma: got {:?}",
            v
        );
    }

    #[test]
    fn empty_value_is_violation() {
        let rule = MessageTimingAllowOriginValidity;
        // header present but empty value -> violation
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("timing-allow-origin", " ")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("empty"));
    }

    #[test]
    fn ipv6_origin_is_valid() {
        let rule = MessageTimingAllowOriginValidity;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("timing-allow-origin", "https://[::1]:8080")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn wildcard_and_origin_mix_is_accepted() {
        let rule = MessageTimingAllowOriginValidity;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("timing-allow-origin", "*, https://example.com")],
        );
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    // § 3.2 terminates an authority at "/", "?" or "#", and a serialized origin
    // ends where its authority does. Only the first of the three reached this
    // rule until the shared validator stopped enumerating them by hand.
    #[rstest]
    #[case("https://a/")]
    #[case("https://a/path")]
    #[case("https://ok.example, https://b/path")]
    #[case("https://a?x=1")]
    #[case("https://a#frag")]
    #[case("https://ok.example, https://b#frag")]
    // The authority's *contents*, unmeasured until the host was asked its own
    // production rather than asked for a space, a tab and an at-sign.
    #[case("https://exa|mple.com")]
    #[case("https://ok.example, https://a<b>c")]
    #[case("https://a%zzb")]
    #[case("https://[foo]")]
    fn member_with_anything_after_the_authority_is_violation(#[case] val: &str) {
        let rule = MessageTimingAllowOriginValidity;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("timing-allow-origin", val)],
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
        let rule = MessageTimingAllowOriginValidity;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("timing-allow-origin", "NULL")],
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
    fn invalid_origin_is_violation() {
        let rule = MessageTimingAllowOriginValidity;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("timing-allow-origin", "https:///foo")],
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
    fn multiple_header_fields_are_combined() {
        use crate::test_helpers::make_headers_from_pairs;
        use hyper::header::HeaderValue;

        let rule = MessageTimingAllowOriginValidity;
        let mut tx = make_test_transaction();
        let mut hdrs = make_headers_from_pairs(&[("timing-allow-origin", "https://a")]);
        hdrs.append("timing-allow-origin", HeaderValue::from_static("https://b"));
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
        assert!(
            v.is_none(),
            "expected no violation for combined fields: got {:?}",
            v
        );
    }

    #[test]
    fn scope_is_server() {
        let rule = MessageTimingAllowOriginValidity;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = MessageTimingAllowOriginValidity;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("error".into()));
        cfg.rules.insert(
            "message_timing_allow_origin_validity".into(),
            toml::Value::Table(table),
        );

        // validate should succeed without error
        rule.validate(&cfg)?;
        Ok(())
    }
}
