// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Validate mutual exclusivity and sanity of conditional request headers.
///
/// Checks include:
/// - `If-Modified-Since` must be ignored when `If-None-Match` is present (flagged here)
/// - `If-Unmodified-Since` must be ignored when `If-Match` is present (flagged here)
/// - `If-Range` MUST not appear without a corresponding `Range` header
/// - `If-Range` MUST NOT contain a weak entity-tag (W/"...")
/// - `If-Modified-Since` is only meaningful for GET/HEAD requests (flag presence on other methods)
pub struct MessageConditionalHeadersConsistency;

impl Rule for MessageConditionalHeadersConsistency {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_conditional_headers_consistency"
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
        // Only applies to requests
        let req = &tx.request;

        let has_if_none_match = req.headers.get("if-none-match").is_some();
        let has_if_modified_since = req.headers.get("if-modified-since").is_some();
        if has_if_none_match && has_if_modified_since {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "If-Modified-Since MUST be ignored when If-None-Match is present; prefer entity-tag conditionals".into(),
            });
        }

        let has_if_match = req.headers.get("if-match").is_some();
        let has_if_unmodified_since = req.headers.get("if-unmodified-since").is_some();
        if has_if_match && has_if_unmodified_since {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "If-Unmodified-Since MUST be ignored when If-Match is present; prefer entity-tag conditionals".into(),
            });
        }

        // If-Range should only be sent in requests that contain Range
        if let Some(hv) = req.headers.get_all("if-range").iter().next() {
            // If-Range exists
            if req.headers.get("range").is_none() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "If-Range present in request without Range header; If-Range MUST only be used with Range requests".into(),
                });
            }

            // Validate If-Range content: if it's an entity-tag, it MUST NOT be weak
            if let Ok(s) = hv.to_str() {
                let trimmed = s.trim();
                // If it looks like an entity-tag (starts with W/ or '"'), check weak
                if trimmed.starts_with("W/") {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "If-Range MUST not contain a weak entity-tag (W/...)".into(),
                    });
                }
                // If it starts with a quoted-string, it's a strong ETag and fine; if it's a date, we'll not flag here
                // (date validity is checked by other rules)
            } else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "If-Range header contains non-UTF8 value".into(),
                });
            }
        }

        // If-Modified-Since only meaningful for GET/HEAD. If present on other methods, flag it.
        if has_if_modified_since
            && !(req.method.eq_ignore_ascii_case("GET") || req.method.eq_ignore_ascii_case("HEAD"))
        {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "If-Modified-Since is only defined for GET/HEAD and MUST be ignored for other methods".into(),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    fn if_modified_since_ignored_when_if_none_match() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("if-none-match", "\"a\""),
            ("if-modified-since", "Wed, 21 Oct 2015 07:28:00 GMT"),
        ]);

        let rule = MessageConditionalHeadersConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
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

        let rule = MessageConditionalHeadersConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
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

        let rule = MessageConditionalHeadersConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
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

        let rule = MessageConditionalHeadersConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
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

        let rule = MessageConditionalHeadersConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
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

        let rule = MessageConditionalHeadersConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
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

        let rule = MessageConditionalHeadersConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
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

        let rule = MessageConditionalHeadersConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
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

        let rule = MessageConditionalHeadersConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
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

        let rule = MessageConditionalHeadersConsistency;
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn scope_is_both() {
        let r = MessageConditionalHeadersConsistency;
        assert_eq!(r.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_conditional_headers_consistency");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
