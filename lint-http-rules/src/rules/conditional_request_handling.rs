// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Stateful checks for conditional requests and their responses.
///
/// - Conditional request headers (`If-None-Match`, `If-Match`, `If-Modified-Since`,
///   `If-Unmodified-Since`) should only be used when the client previously
///   observed a validator (ETag or Last-Modified) for the same resource.
/// - For `If-None-Match` / `If-Modified-Since` on `GET`/`HEAD`, a response that
///   matches the validator SHOULD be `304 Not Modified` rather than a `200`.
pub struct ConditionalRequestHandling;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9110_13_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("13.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1",
    note: "Preconditions",
};
const RFC_9110_13_1_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("13.1.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.2",
    note: "If-None-Match: GET/HEAD with a false condition MUST get 304",
};
const RFC_9110_13_1_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("13.1.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.3",
    note: "If-Modified-Since: a false condition SHOULD get 304",
};
const RFC_9110_13_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("13.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-13.2",
    note: "Evaluation of Preconditions (precedence rules)",
};
const RFC_9110_8_8_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("8.8.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3",
    note: "ETag header field",
};
const RFC_9110_8_8_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("8.8.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.2",
    note: "Last-Modified header field",
};

/// Which preconditions a request carried.
///
/// The four fields are asked in three different groupings — the two entity-tag
/// ones together, the two date ones together, and `If-None-Match` alone, which
/// § 13.2.2 makes govern whether `If-Modified-Since` is evaluated at all — and
/// naming the groupings is what keeps a check from testing the wrong pair.
struct Preconditions {
    if_none_match: bool,
    if_match: bool,
    if_modified_since: bool,
    if_unmodified_since: bool,
}

impl Preconditions {
    fn of(headers: &hyper::HeaderMap) -> Self {
        Self {
            if_none_match: headers.contains_key("if-none-match"),
            if_match: headers.contains_key("if-match"),
            if_modified_since: headers.contains_key("if-modified-since"),
            if_unmodified_since: headers.contains_key("if-unmodified-since"),
        }
    }

    /// Whether the request is conditional at all.
    fn any(&self) -> bool {
        self.if_none_match || self.if_match || self.if_modified_since || self.if_unmodified_since
    }

    /// Whether a precondition compares against an entity-tag validator.
    fn entity_tag(&self) -> bool {
        self.if_none_match || self.if_match
    }

    /// Whether a precondition compares against a modification date.
    fn date(&self) -> bool {
        self.if_modified_since || self.if_unmodified_since
    }
}

/// The two methods whose failed precondition is answered with 304 rather than
/// 412, which is what makes the checks below about a `200` at all.
// cite(RFC 9110 § 13.1.2): "the 304 (Not Modified) status code if the request method is GET or HEAD"
fn is_get_or_head(method: &str) -> bool {
    method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD")
}

impl ConditionalRequestHandling {
    /// A precondition carries validator metadata from a stored response, so a
    /// client sending one should have been given that validator.
    ///
    /// Requiring the client to have *previously observed* the validator is a
    /// stateful heuristic with no governing MUST/SHOULD in RFC 9110 (recorded
    /// §4.1) — `If-None-Match: *` legitimately needs no prior tag — so none of
    /// these findings carries a cite.
    fn validator_was_observed(
        &self,
        sent: &Preconditions,
        history: &crate::transaction_history::TransactionHistory,
        severity: crate::lint::Severity,
    ) -> Option<Violation> {
        let Some(prev) = history.previous() else {
            return Some(self.violation(severity, "Conditional request sent but no previous response recorded for this resource (no ETag/Last-Modified to validate against)".into()));
        };
        let Some(resp) = &prev.response else {
            return Some(self.violation(
                severity,
                "Conditional request sent but previous transaction has no response recorded".into(),
            ));
        };
        if sent.entity_tag() && !resp.headers.contains_key("etag") {
            return Some(self.violation(severity, "Request contains entity-tag conditional (If-Match/If-None-Match) but previous response did not include an ETag".into()));
        }
        if sent.date() && !resp.headers.contains_key("last-modified") {
            return Some(self.violation(severity, "Request contains time-based conditional (If-Modified-Since/If-Unmodified-Since) but previous response did not include Last-Modified".into()));
        }
        None
    }

    /// A GET or HEAD whose `If-None-Match` condition is false is answered with
    /// 304, not 200.
    ///
    /// The members are compared exactly rather than by the weak comparison
    /// § 8.8.3.2 mandates: a deliberate narrowing that only ever under-flags,
    /// since an exact match is also a weak match.
    // cite(RFC 9110 § 13.1.2): "An origin server that evaluates an If-None-Match condition MUST NOT perform the requested method if the condition evaluates to false; instead, the origin server MUST respond with either a) the 304 (Not Modified) status code if the request method is GET or HEAD or b) the 412 (Precondition Failed) status code for all other request methods."
    fn if_none_match_was_evaluated(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        sent: &Preconditions,
        severity: crate::lint::Severity,
    ) -> Option<Violation> {
        if !sent.if_none_match || !is_get_or_head(&tx.request.method) {
            return None;
        }
        let resp = tx.response.as_ref()?;
        if resp.status != 200 {
            return None;
        }
        let etag = crate::helpers::headers::get_header_str(&resp.headers, "etag")?.trim();
        let condition_was_false =
            crate::helpers::headers::field_lines(&tx.request.headers, "if-none-match")
                .flat_map(crate::helpers::list::list_members)
                .any(|member| member == etag || member == "*");

        condition_was_false.then(|| self.violation(severity, "Conditional GET/HEAD: the If-None-Match condition was not met (response ETag matched) but the server returned 200; RFC 9110 §13.1.2 requires a 304 (Not Modified) for GET/HEAD".into()))
    }

    /// A GET or HEAD whose `If-Modified-Since` condition is false should be
    /// answered with 304 — a SHOULD here, unlike § 13.1.2's MUST.
    ///
    /// Asked only where `If-None-Match` is absent: § 13.2.2 evaluates
    /// `If-Modified-Since` only then, so with both present the check above
    /// governs and a 200 may be perfectly legal.
    // cite(RFC 9110 § 13.1.3): "An origin server that evaluates an If-Modified-Since condition SHOULD NOT perform the requested method if the condition evaluates to false; instead, the origin server SHOULD generate a 304 (Not Modified) response"
    // cite(RFC 9110 § 13.2.2): "When the method is GET or HEAD, If-None-Match is not present, and If-Modified-Since is present, evaluate the If-Modified-Since precondition"
    fn if_modified_since_was_evaluated(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        sent: &Preconditions,
        severity: crate::lint::Severity,
    ) -> Option<Violation> {
        if !sent.if_modified_since || sent.if_none_match || !is_get_or_head(&tx.request.method) {
            return None;
        }
        let resp = tx.response.as_ref()?;
        if resp.status != 200 {
            return None;
        }
        let since = crate::http_date::header_timestamp(&tx.request.headers, "if-modified-since")?;
        let last_modified = crate::http_date::header_timestamp(&resp.headers, "last-modified")?;

        (last_modified <= since).then(|| self.violation(severity, "Conditional GET/HEAD used If-Modified-Since but server returned 200 even though Last-Modified indicates the resource was not modified; consider returning 304 Not Modified".into()))
    }
}

impl Rule for ConditionalRequestHandling {
    fn id(&self) -> &'static str {
        "conditional_request_handling"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            let sent = Preconditions::of(&tx.request.headers);
            if !sent.any() {
                return None;
            }
            self.validator_was_observed(&sent, history, ctx.severity)
                .or_else(|| self.if_none_match_was_evaluated(tx, &sent, ctx.severity))
                .or_else(|| self.if_modified_since_was_evaluated(tx, &sent, ctx.severity))
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "Warn when conditional requests are used without a prior validator (ETag / Last-Modified) observed for the same resource and client. Also flag obvious cases where a server returns a `200` for a conditional `GET`/`HEAD` when the validator clearly matches (the server should return `304 Not Modified`)."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_13_1,
            RFC_9110_13_1_2,
            RFC_9110_13_1_3,
            RFC_9110_13_2,
            RFC_9110_8_8_3,
            RFC_9110_8_8_2,
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "> GET /resource HTTP/1.1\n> If-None-Match: \"abc\"\n\n< 304 Not Modified  HTTP/1.1\n< ETag: \"abc\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— conditional request with no prior validator recorded"),
                snippet: "> GET /resource HTTP/1.1\n> If-None-Match: \"abc\"\n\n< 200 OK  HTTP/1.1\n< ETag: \"abc\"\n< (body)",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— client used conditional header without previously seeing an ETag/Last-Modified"),
                snippet: "> GET /resource HTTP/1.1\n> If-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT\n\n< 200 OK  HTTP/1.1\n< Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ConditionalRequestHandling;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_prev_with_headers(
        headers: &[(&str, &str)],
    ) -> crate::http_transaction::HttpTransaction {
        let mut prev = crate::test_helpers::make_test_transaction_with_response(200, headers);
        prev.request.method = "GET".to_string();
        prev
    }

    #[test]
    fn conditional_request_without_previous_is_reported() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);

        let rule = ConditionalRequestHandling;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("no previous response recorded"));
    }

    #[test]
    fn conditional_request_requires_matching_previous_validator() {
        let rule = ConditionalRequestHandling;

        // If-None-Match without previous ETag -> violation
        let mut tx1 = crate::test_helpers::make_test_transaction();
        tx1.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        let prev_empty = make_prev_with_headers(&[]);
        let v1 = crate::test_helpers::run_rule(
            &rule,
            &tx1,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![
                prev_empty.clone()
            ]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        );
        assert!(v1.is_some());

        // If-Modified-Since without previous Last-Modified -> violation
        let mut tx2 = crate::test_helpers::make_test_transaction();
        tx2.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-modified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);
        let v2 = crate::test_helpers::run_rule(
            &rule,
            &tx2,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![
                prev_empty.clone()
            ]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        );
        assert!(v2.is_some());

        // If-Match without previous ETag -> violation
        let mut tx3 = crate::test_helpers::make_test_transaction();
        tx3.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-match", "\"a\"")]);
        let v3 = crate::test_helpers::run_rule(
            &rule,
            &tx3,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![
                prev_empty.clone()
            ]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        );
        assert!(v3.is_some());

        // If-Unmodified-Since without previous Last-Modified -> violation
        let mut tx4 = crate::test_helpers::make_test_transaction();
        tx4.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-unmodified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);
        let v4 = crate::test_helpers::run_rule(
            &rule,
            &tx4,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![
                prev_empty.clone()
            ]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        );
        assert!(v4.is_some());
    }

    #[test]
    fn conditional_request_with_prev_etag_or_lm_ok() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);

        // previous response with ETag
        let prev = make_prev_with_headers(&[("etag", "\"a\"")]);

        let rule = ConditionalRequestHandling;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev.clone()]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        );
        assert!(v.is_none());

        // time-based conditional with Last-Modified
        let mut tx2 = crate::test_helpers::make_test_transaction();
        tx2.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-modified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);
        let prev2 = make_prev_with_headers(&[("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")]);
        let v2 = crate::test_helpers::run_rule(
            &rule,
            &tx2,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev2.clone()]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        );
        assert!(v2.is_none());
    }

    #[test]
    fn inm_response_matching_etag_reports_violation_for_get() {
        let mut tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[("etag", "\"a\"")]);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        tx.request.method = "GET".to_string();

        let prev = make_prev_with_headers(&[("etag", "\"a\"")]);

        let rule = ConditionalRequestHandling;
        // previous satisfies validator check
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev.clone()]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("304"));
        assert!(msg.contains("§13.1.2"));
    }

    #[test]
    fn if_modified_since_response_matching_lm_reports_violation_for_get() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")],
        );
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-modified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        )]);
        tx.request.method = "GET".to_string();

        let prev = make_prev_with_headers(&[("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")]);

        let rule = ConditionalRequestHandling;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev.clone()]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("consider returning 304"));
    }

    #[test]
    fn ims_304_not_flagged_when_if_none_match_present() {
        // Both If-None-Match and If-Modified-Since present. Per RFC 9110 §13.2.2, only
        // If-None-Match is evaluated; its condition is TRUE here (response ETag "b" does not
        // match the request tag "a"), so the 200 is legal and the If-Modified-Since→304
        // check must NOT fire even though Last-Modified is not more recent than the IMS value.
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("etag", "\"b\""),
                ("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT"),
            ],
        );
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("if-none-match", "\"a\""),
            ("if-modified-since", "Wed, 21 Oct 2015 07:28:00 GMT"),
        ]);
        tx.request.method = "GET".to_string();

        let prev = make_prev_with_headers(&[
            ("etag", "\"a\""),
            ("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT"),
        ]);

        let rule = ConditionalRequestHandling;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev.clone()]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        );
        assert!(
            v.is_none(),
            "IMS→304 must not fire when If-None-Match is present: {v:?}"
        );
    }

    #[test]
    fn if_none_match_non_matching_etag_is_ok() {
        let mut tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[("etag", "\"b\"")]);
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        tx.request.method = "GET".to_string();

        let prev = make_prev_with_headers(&[("etag", "\"a\"")]);

        let rule = ConditionalRequestHandling;
        // response ETag doesn't match request conditional -> allowed
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev.clone()]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn previous_without_response_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);

        // previous transaction exists but has no response
        let prev = crate::test_helpers::make_test_transaction();

        let rule = ConditionalRequestHandling;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev.clone()]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "conditional_request_handling",
            ]),
        );
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .contains("previous transaction has no response recorded"));
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "conditional_request_handling");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
