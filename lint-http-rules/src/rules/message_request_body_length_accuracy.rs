// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageRequestBodyLengthAccuracy;

impl Rule for MessageRequestBodyLengthAccuracy {
    fn id(&self) -> &'static str {
        "message_request_body_length_accuracy"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let req = &tx.request;

        // This rule used to transcribe the whole `Content-Length` grammar
        // inline -- `1*DIGIT`, the u128 ceiling, the multiple-values-differ
        // check, the non-UTF8 branch -- and emit findings for each, with
        // message strings byte-identical to `message_content_length`'s. That
        // rule owns the field's syntax, on both sides, and delegates to
        // `validate_content_length`. So every malformed value here produced two
        // identical findings for one defect.
        //
        // Worse, the copy had fallen behind the original. § 6.3 makes a
        // comma-separated list valid when every value parses and they all
        // agree, and says what such a message means; the helper implements
        // that, and the inline copy rejected `Content-Length: 5, 5` as an
        // invalid value.
        // cite(RFC 9112 § 6.3): "If a message is received without Transfer-Encoding and with an invalid Content-Length header field, then the message framing is invalid and the recipient MUST treat it as an unrecoverable error, unless the field value can be successfully parsed as a comma-separated list (Section 5.6.1 of [HTTP]), all values in the list are valid, and all values in the list are the same (in which case, the message is processed with that single value used as the Content-Length field value)."
        //
        // Nothing is re-quoted here on purpose. A syntax error means there is
        // no number to compare a body against, so this rule declines and
        // `message_content_length` makes the report.
        // cite(RFC 9112 § 6.3): "The length of a message body is determined by one of the following (in order of precedence)"
        let declared = crate::helpers::headers::validate_content_length(&req.headers).ok()??;

        // Compare to captured body length when available
        if let Some(body_len) = req.body_length {
            if declared != body_len as u128 {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "Content-Length ({}) does not match captured body bytes ({})",
                        declared, body_len
                    ),
                });
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "When a request includes a `Content-Length` header, its numeric value MUST match the actual length in bytes of the captured request body after HTTP framing has been resolved (for example, after processing chunked transfer-coding), but not necessarily after any `Content-Encoding` (such as gzip) has been decoded. Mismatches indicate truncated or malformed requests and can lead to framing errors or request smuggling vulnerabilities. This rule validates that `Content-Length` (when present and syntactically valid) equals the captured body length recorded in the transaction."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("6.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6.2",
                note: "Content-Length header field usage",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("6.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3",
                note: "Message body length determination and framing (how body length is determined and handled)",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "POST /upload HTTP/1.1\nContent-Length: 3\n\nabc",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(mismatched Content-Length)"),
                snippet: "POST /upload HTTP/1.1\nContent-Length: 10\n\nabc",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(invalid Content-Length)"),
                snippet: "POST /upload HTTP/1.1\nContent-Length: abc\n\nabc",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageRequestBodyLengthAccuracy;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn matching_content_length_and_body_no_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request = crate::http_transaction::RequestInfo {
            method: "POST".into(),
            uri: "http://example/".into(),
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("content-length", "3")]),
            body_length: Some(3),
            trailers: None,
        };

        let rule = MessageRequestBodyLengthAccuracy;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn mismatching_content_length_and_body_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request = crate::http_transaction::RequestInfo {
            method: "POST".into(),
            uri: "http://example/".into(),
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("content-length", "10")]),
            body_length: Some(3),
            trailers: None,
        };

        let rule = MessageRequestBodyLengthAccuracy;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Content-Length"));
    }

    #[test]
    fn no_content_length_present_no_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request = crate::http_transaction::RequestInfo {
            method: "POST".into(),
            uri: "http://example/".into(),
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[]),
            body_length: Some(5),
            trailers: None,
        };

        let rule = MessageRequestBodyLengthAccuracy;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn content_length_present_but_no_captured_body_no_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request = crate::http_transaction::RequestInfo {
            method: "POST".into(),
            uri: "http://example/".into(),
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("content-length", "3")]),
            body_length: None,
            trailers: None,
        };

        let rule = MessageRequestBodyLengthAccuracy;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn multiple_identical_content_length_headers_no_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        use hyper::header::HeaderValue;
        hm.append("content-length", HeaderValue::from_static("10"));
        hm.append("content-length", HeaderValue::from_static("10"));
        tx.request = crate::http_transaction::RequestInfo {
            method: "POST".into(),
            uri: "http://example/".into(),
            version: "HTTP/1.1".into(),
            headers: hm,
            body_length: Some(10),
            trailers: None,
        };

        let rule = MessageRequestBodyLengthAccuracy;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn whitespace_in_content_length_is_accepted() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request = crate::http_transaction::RequestInfo {
            method: "POST".into(),
            uri: "http://example/".into(),
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[("content-length", "  3  ")]),
            body_length: Some(3),
            trailers: None,
        };

        let rule = MessageRequestBodyLengthAccuracy;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    fn req_with(
        headers: &[(&str, &str)],
        body_length: Option<u64>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request = crate::http_transaction::RequestInfo {
            method: "POST".into(),
            uri: "http://example/".into(),
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(headers),
            body_length,
            trailers: None,
        };
        tx
    }

    fn run(tx: &crate::http_transaction::HttpTransaction) -> Option<crate::lint::Violation> {
        let rule = MessageRequestBodyLengthAccuracy;
        rule.check_transaction(
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    /// A malformed value leaves no number to compare a body against, so this
    /// rule declines and `message_content_length` -- which owns the field's
    /// syntax on both sides and reports these with the same message strings --
    /// makes the report. These five used to be duplicated here.
    #[rstest]
    #[case("abc")]
    #[case("+1")]
    #[case("")]
    #[case("340282366920938463463374607431768211456")]
    fn a_malformed_value_is_left_to_the_rule_that_owns_the_syntax(#[case] cl: &str) {
        let tx = req_with(&[("content-length", cl)], Some(3));
        assert!(run(&tx).is_none(), "{cl:?} is the syntax rule's finding");
    }

    /// The same, for values that disagree across field lines.
    #[test]
    fn values_that_disagree_are_left_to_the_syntax_rule() {
        use hyper::header::HeaderValue;
        let mut tx = req_with(&[], Some(10));
        let mut hm = hyper::HeaderMap::new();
        hm.append("content-length", HeaderValue::from_static("10"));
        hm.append("content-length", HeaderValue::from_static("20"));
        tx.request.headers = hm;
        assert!(run(&tx).is_none());
    }

    /// A value the sending side never wrote as a violation: § 6.3 makes a
    /// comma-separated list valid when every value parses and they all agree,
    /// and says the message is processed with that single value. The inline
    /// copy of the grammar rejected this; the helper has always accepted it.
    #[rstest]
    #[case("3, 3", Some(3), false)]
    #[case("3, 3", Some(4), true)]
    fn a_comma_list_of_equal_values_is_one_value(
        #[case] cl: &str,
        #[case] body: Option<u64>,
        #[case] expect: bool,
    ) {
        let tx = req_with(&[("content-length", cl)], body);
        assert_eq!(run(&tx).is_some(), expect, "{cl:?} vs {body:?}");
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_request_body_length_accuracy");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn validate_rules_with_invalid_config_missing_severity() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_request_body_length_accuracy");
        // remove severity to simulate invalid config
        if let Some(toml::Value::Table(ref mut table)) =
            cfg.rules.get_mut("message_request_body_length_accuracy")
        {
            table.remove("severity");
        }

        let err = crate::rules::validate_rules(&cfg).expect_err("expected validation to fail");
        assert!(err.to_string().contains("Missing required 'severity'"));
    }
}
