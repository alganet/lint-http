// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};

/// Validate mutual exclusivity and sanity of conditional request headers.
///
/// Checks include:
/// - `If-Modified-Since` must be ignored when `If-None-Match` is present (flagged here)
/// - `If-Unmodified-Since` must be ignored when `If-Match` is present (flagged here)
/// - `If-Range` MUST not appear without a corresponding `Range` header
/// - `If-Range` MUST NOT contain a weak entity-tag (W/"...")
/// - `If-Modified-Since` is only meaningful for GET/HEAD requests (flag presence on other methods)
pub struct ConditionalHeadersConsistent;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_13_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("13.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1",
    note: "Preconditions",
};
const RFC_9110_13_1_5: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("13.1.5"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.5",
    note: "If-Range: no If-Range without Range; no weak entity-tag in If-Range",
};
const RFC_9110_13_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("13.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.2",
    note: "Evaluation of Preconditions (precedence rules)",
};
const RFC_9110_14_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("14.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-14.2",
    note: "Range (the header If-Range depends on)",
};

impl RuleMeta for ConditionalHeadersConsistent {
    fn id(&self) -> &'static str {
        "conditional_headers_consistent"
    }

    fn description(&self) -> &'static str {
        "Validate consistency and mutual exclusivity of conditional request headers. When an ETag-based conditional is present, this rule flags a redundant date-based conditional that the recipient is required to ignore (RFC 9110 §13.1.3, §13.1.4); it also ensures `If-Range` is only used with `Range` requests, disallows a weak entity-tag in `If-Range`, flags `If-Modified-Since` on methods other than GET/HEAD, and flags a repeated `If-Modified-Since`/`If-Unmodified-Since` field, whose combined value is a list of dates the recipient must ignore."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9110_13_1, RFC_9110_13_1_5, RFC_9110_13_2, RFC_9110_14_2]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nIf-None-Match: \"abc\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nRange: bytes=0-99\nIf-Range: \"abc\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "POST /resource HTTP/1.1\nHost: example.com\nIf-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT   # If-Modified-Since is not meaningful for POST",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nIf-None-Match: \"abc\"\nIf-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT   # If-Modified-Since MUST be ignored when If-None-Match present",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nRange: bytes=0-99\nIf-Range: W/\"weaktag\"   # If-Range must not contain a weak entity-tag",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET /resource HTTP/1.1\nHost: example.com\nIf-Range: \"strongtag\"   # missing Range header -> invalid use of If-Range",
            },
        ]
    }
}

impl Rule for ConditionalHeadersConsistent {
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            // Only applies to requests
            let req = &tx.request;

            let has_if_none_match = req.headers.get("if-none-match").is_some();
            let has_if_modified_since = req.headers.get("if-modified-since").is_some();
            // cite(RFC 9110 § 13.1.3): "A recipient MUST ignore If-Modified-Since if the request contains an If-None-Match header field"
            if has_if_none_match && has_if_modified_since {
                return Some(self.violation(ctx.severity, "If-Modified-Since MUST be ignored when If-None-Match is present; prefer entity-tag conditionals".into()));
            }

            let has_if_match = req.headers.get("if-match").is_some();
            let has_if_unmodified_since = req.headers.get("if-unmodified-since").is_some();
            // cite(RFC 9110 § 13.1.4): "A recipient MUST ignore If-Unmodified-Since if the request contains an If-Match header field"
            if has_if_match && has_if_unmodified_since {
                return Some(self.violation(ctx.severity, "If-Unmodified-Since MUST be ignored when If-Match is present; prefer entity-tag conditionals".into()));
            }

            // If-Range should only be sent in requests that contain Range
            if let Some(hv) = req.headers.get_all("if-range").iter().next() {
                // If-Range exists
                // cite(RFC 9110 § 13.1.5): "A client MUST NOT generate an If-Range header field in a request that does not contain a Range header field."
                if req.headers.get("range").is_none() {
                    return Some(self.cited(&RFC_9110_13_1_5, ctx.severity, "If-Range present in request without Range header; If-Range MUST only be used with Range requests".into()));
                }

                // Validate If-Range content: if it's an entity-tag, it MUST NOT be weak.
                // (A weak marker is the `W/` prefix; a bare quoted-string is a strong tag and
                // fine, and a date is left to date-validity rules.)
                let Ok(s) = hv.to_str() else {
                    return Some(self.violation(
                        ctx.severity,
                        "If-Range header contains non-UTF8 value".into(),
                    ));
                };
                let trimmed = s.trim();
                // cite(RFC 9110 § 13.1.5): "A client MUST NOT generate an If-Range header field containing an entity tag that is marked as weak."
                if trimmed.starts_with("W/") {
                    return Some(self.cited(
                        &RFC_9110_13_1_5,
                        ctx.severity,
                        "If-Range MUST not contain a weak entity-tag (W/...)".into(),
                    ));
                }
                // If it starts with a quoted-string, it's a strong ETag and fine; if it's a date, we'll not flag here
                // (date validity is checked by other rules)
            }

            // Neither date conditional is a list, so a second field line is a sender
            // violation — and the combined value the recipient sees is then "more than one
            // member" / "a list of dates", which it MUST ignore. The conditional silently
            // degrades to an unconditional request, which is the harm worth reporting.
            // Each line on its own may be a perfectly valid HTTP-date, so the date-format
            // rules (which validate line by line) cannot see this; only the count can.
            // cite(RFC 9110 § 5.3): "a sender MUST NOT generate multiple field lines with the same name in a message (whether in the headers or trailers) or append a field line when a field line of the same name already exists in the message, unless that field's definition allows multiple field line values to be recombined as a comma-separated list"
            // Each field's own recipient consequence — the two are worded differently
            // ("more than one member" vs "appears to be a list of dates") but bite alike.
            // cite(RFC 9110 § 13.1.3): "A recipient MUST ignore the If-Modified-Since header field if the received field value is not a valid HTTP-date, the field value has more than one member, or if the request method is neither GET nor HEAD."
            // cite(RFC 9110 § 13.1.4): "A recipient MUST ignore the If-Unmodified-Since header field if the received field value is not a valid HTTP-date (including when the field value appears to be a list of dates)."
            for (name, label) in [
                ("if-modified-since", "If-Modified-Since"),
                ("if-unmodified-since", "If-Unmodified-Since"),
            ] {
                if req.headers.get_all(name).iter().count() > 1 {
                    return Some(self.violation(ctx.severity, format!(
                            "Multiple {} header fields present; the combined value is a list of dates, which the recipient MUST ignore",
                            label
                        )));
                }
            }

            // If-Modified-Since only meaningful for GET/HEAD. If present on other methods, flag it.
            // (The cited sentence bundles three ignore-conditions; this rule enforces the
            // method one and, above, the multiplicity one. The not-a-valid-HTTP-date clause
            // is owned by the date-format rule.)
            // cite(RFC 9110 § 13.1.3): "A recipient MUST ignore the If-Modified-Since header field if the received field value is not a valid HTTP-date, the field value has more than one member, or if the request method is neither GET nor HEAD."
            if has_if_modified_since
                && !(req.method.eq_ignore_ascii_case("GET")
                    || req.method.eq_ignore_ascii_case("HEAD"))
            {
                return Some(self.violation(ctx.severity, "If-Modified-Since is only defined for GET/HEAD and MUST be ignored for other methods".into()));
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ConditionalHeadersConsistent;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Two field lines, each on its own a perfectly valid HTTP-date — so the
    /// line-by-line date-format rules see nothing wrong. Only the count reveals
    /// that the recipient will discard the conditional entirely.
    #[rstest]
    #[case("if-modified-since", "If-Modified-Since")]
    #[case("if-unmodified-since", "If-Unmodified-Since")]
    fn multiple_date_conditional_field_lines_are_violation(
        #[case] header: &'static str,
        #[case] label: &str,
    ) {
        use hyper::header::HeaderValue;

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            header,
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);
        tx.request.headers.append(
            header,
            HeaderValue::from_static("Thu, 22 Oct 2015 07:28:00 GMT"),
        );

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let v = v.unwrap_or_else(|| panic!("expected violation for two {} lines", label));
        assert!(v.message.contains(label));
        assert!(v.message.contains("list of dates"));
    }

    #[rstest]
    #[case("if-modified-since")]
    #[case("if-unmodified-since")]
    fn single_date_conditional_field_line_is_fine(#[case] header: &'static str) {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            header,
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "unexpected violation: {:?}", v);
    }

    #[rstest]
    fn if_modified_since_ignored_when_if_none_match() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("if-none-match", "\"a\""),
            ("if-modified-since", "Wed, 21 Oct 2015 07:28:00 GMT"),
        ]);

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("If-Modified-Since MUST be ignored"));
    }

    #[rstest]
    fn if_unmodified_since_ignored_when_if_match() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("if-match", "\"a\""),
            ("if-unmodified-since", "Wed, 21 Oct 2015 07:28:00 GMT"),
        ]);

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("If-Unmodified-Since MUST be ignored"));
    }

    #[rstest]
    fn if_range_without_range_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("if-range", "\"a\"")]);

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("without Range"));
    }

    #[rstest]
    fn if_range_with_weak_etag_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("range", "bytes=0-1"),
            ("if-range", "W/\"abc\""),
        ]);

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("MUST not contain a weak"));
    }

    #[rstest]
    fn if_range_with_non_utf8_reports_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.insert("range", "bytes=0-1".parse().unwrap());
        // Create a non-UTF8 header value by using arbitrary bytes that don't form valid UTF-8
        let non_utf8 = HeaderValue::from_bytes(&[0xFF, 0xFF]).expect("create header value");
        hm.insert("if-range", non_utf8);
        tx.request.headers = hm;

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("non-UTF8"));
    }

    #[rstest]
    fn if_range_with_date_is_ok() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("range", "bytes=0-1"),
            ("if-range", "Wed, 21 Oct 2015 07:28:00 GMT"),
        ]);

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[rstest]
    fn if_modified_since_on_post_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "POST".to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-modified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("only defined for GET/HEAD"));
    }

    #[rstest]
    fn if_modified_since_on_get_is_ok() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-modified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[rstest]
    fn if_modified_since_on_head_is_ok() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "HEAD".to_string();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-modified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn no_violation_for_happy_path() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("range", "bytes=0-1"),
            ("if-range", "\"abc\""),
            ("if-match", "\"a\""),
        ]);

        let rule = ConditionalHeadersConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn scope_is_both() {
        let r = ConditionalHeadersConsistent;
        assert_eq!(r.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "conditional_headers_consistent");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
