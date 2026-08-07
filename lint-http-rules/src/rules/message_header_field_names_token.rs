// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageHeaderFieldNamesToken;

impl Rule for MessageHeaderFieldNamesToken {
    fn id(&self) -> &'static str {
        "message_header_field_names_token"
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
        // token characters per RFC token (tchar) - use shared helper
        // Check request headers
        // cite(RFC 9110 § 5.1): "Field names are case-insensitive and ought to be registered within the "Hypertext Transfer Protocol (HTTP) Field Name Registry""
        if let Some(v) = check_section("request header section", &tx.request.headers, &config) {
            return Some(v);
        }
        if let Some(trailers) = &tx.request.trailers {
            if let Some(v) = check_section("request trailer section", trailers, &config) {
                return Some(v);
            }
        }

        // Check response headers if present
        if let Some(resp) = &tx.response {
            if let Some(v) = check_section("response header section", &resp.headers, &config) {
                return Some(v);
            }
            if let Some(trailers) = &resp.trailers {
                if let Some(v) = check_section("response trailer section", trailers, &config) {
                    return Some(v);
                }
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "This rule validates that **field names** conform to the `token` grammar. Field names containing control characters, spaces, or other separator characters are invalid and can indicate protocol violations or injection attempts.\n\nThe rule flags field names that contain characters outside the allowed `tchar` set (letters, digits, and the following characters: ``! # $ % & ' * + - . ^ _ ` | ~``). One grammar governs every field section, so the request and response header sections are checked and so are their trailer sections when the message framing carried one."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[crate::rules::SpecRef {
            spec: "RFC 9110",
            section: Some("5.1"),
            url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.1",
            note: "Field Names",
        }]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Host: example.com\nContent-Type: text/plain\nX-Custom-Header: v",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Bad Header: v\nX@Bad: v\nheader:with:colon: v",
            },
        ]
    }
}

/// Walk one field section, reporting the first field name that is not a `token`.
fn check_section(
    section: &str,
    fields: &hyper::HeaderMap,
    config: &crate::rules::RuleConfig,
) -> Option<Violation> {
    for (k, _v) in fields.iter() {
        if let Some(v) = check_header_name(section, k.as_str(), config) {
            return Some(v);
        }
    }
    None
}

// Extracted helper to make the message/violation formatting testable without needing
// to construct invalid `HeaderName` values (which hyper often rejects).
fn check_header_name(
    section: &str,
    name: &str,
    config: &crate::rules::RuleConfig,
) -> Option<Violation> {
    if let Some(c) = crate::helpers::token::find_invalid_token_char(name) {
        return Some(Violation {
            rule: MessageHeaderFieldNamesToken.id().into(),
            severity: config.severity,
            message: format!(
                "Field name '{}' in the {} contains invalid character: '{}'",
                name, section, c
            ),
        });
    }
    None
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageHeaderFieldNamesToken;

#[cfg(test)]
mod tests {
    use super::*;

    use hyper::header::{HeaderName, HeaderValue};
    use rstest::rstest;

    /// A field section holding one name that `HeaderName`'s HTTP/1 parser would
    /// reject: `from_lowercase` is the constructor the HTTP/2 and HTTP/3 decoders
    /// use, and its table admits DQUOTE.
    fn section_with(name: &str, value: &str) -> hyper::HeaderMap {
        let mut hm = hyper::HeaderMap::new();
        hm.append(
            HeaderName::from_lowercase(name.as_bytes()).expect("h2/h3 decoders accept this name"),
            HeaderValue::from_str(value).expect("valid field value"),
        );
        hm
    }

    #[rstest]
    #[case(vec![("host", "example")], false)]
    #[case(vec![("content-type", "text/plain")], false)]
    #[case(vec![("x-custom-header", "v")], false)]
    fn check_request_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageHeaderFieldNamesToken;

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(header_pairs.as_slice());

        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );

        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[rstest]
    #[case(vec![("etag", "\"abc\"")], false)]
    fn check_response_cases(
        #[case] header_pairs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessageHeaderFieldNamesToken;

        let tx =
            crate::test_helpers::make_test_transaction_with_response(200, header_pairs.as_slice());

        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );

        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    /// The domain the rule actually polices. The HTTP/1 field-name parser is the
    /// `token` grammar exactly, so a name it accepts can never violate this rule;
    /// the HTTP/2 and HTTP/3 decoders admit one character the grammar does not.
    #[rstest]
    #[case("x@bad")]
    #[case("bad header")]
    #[case("header:with:colon")]
    fn names_the_http1_parser_rejects_never_reach_the_rule(#[case] name: &str) {
        assert!(
            HeaderName::from_bytes(name.as_bytes()).is_err(),
            "'{}' would reach a HeaderMap, so the rule must be tested on it",
            name
        );
    }

    #[test]
    fn dquote_name_is_the_reachable_violation() {
        assert!(
            HeaderName::from_bytes(b"x\"bad").is_err(),
            "the HTTP/1 parser must keep DQUOTE out"
        );
        let name = HeaderName::from_lowercase(b"x\"bad").expect("h2/h3 decoders convey DQUOTE");
        assert_eq!(name.as_str(), "x\"bad");
    }

    #[rstest]
    #[case("host", false, None)]
    #[case("x\"bad", true, Some('"'))]
    fn check_header_name_helper_cases(
        #[case] name: &str,
        #[case] expect_violation: bool,
        #[case] expected_char: Option<char>,
    ) -> anyhow::Result<()> {
        let cfg = &crate::test_helpers::make_test_rule_config();
        let res = super::check_header_name("request header section", name, cfg);

        if expect_violation {
            assert!(res.is_some(), "expected violation for '{}'", name);
            let v = res.unwrap();
            assert!(v.message.contains(name));
            assert!(v.message.contains("request header section"));
            if let Some(c) = expected_char {
                assert!(v.message.contains(&c.to_string()));
            }
        } else {
            assert!(res.is_none(), "expected no violation for '{}'", name);
        }
        Ok(())
    }

    /// Every field section of the transaction is walked, and the violation names
    /// the one the field came from.
    #[rstest]
    #[case::request_headers("request header section")]
    #[case::request_trailers("request trailer section")]
    #[case::response_headers("response header section")]
    #[case::response_trailers("response trailer section")]
    fn dquote_field_name_is_flagged_in_every_section(#[case] section: &str) {
        let rule = MessageHeaderFieldNamesToken;
        let bad = section_with("x\"bad", "v");

        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "text/plain")],
        );
        match section {
            "request header section" => tx.request.headers = bad,
            "request trailer section" => tx.request.trailers = Some(bad),
            "response header section" => tx.response.as_mut().unwrap().headers = bad,
            "response trailer section" => tx.response.as_mut().unwrap().trailers = Some(bad),
            other => panic!("unknown section {}", other),
        }

        let violation = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );

        let v = violation.expect("DQUOTE field name must be flagged");
        assert!(
            v.message.contains(section),
            "violation should name the section it came from, got: {}",
            v.message
        );
        assert!(v.message.contains("x\"bad"));
    }

    #[test]
    fn valid_trailer_field_names_are_not_flagged() {
        let rule = MessageHeaderFieldNamesToken;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("trailer", "x-checksum")],
        );
        tx.request.trailers = Some(crate::test_helpers::make_headers_from_pairs(&[(
            "x-request-checksum",
            "abc",
        )]));
        tx.response.as_mut().unwrap().trailers = Some(
            crate::test_helpers::make_headers_from_pairs(&[("x-checksum", "abc123")]),
        );

        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            )
            .is_none());
    }

    #[test]
    fn scope_is_both() {
        let rule = MessageHeaderFieldNamesToken;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
