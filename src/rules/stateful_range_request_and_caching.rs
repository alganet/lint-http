// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Stateful check ensuring that caches reusing partial (206) responses
/// validate them before attempting to satisfy a new Range request.
///
/// Per RFC 7233 §3.2 and §4.3, a cache that has stored a 206 Partial Content
/// response SHOULD include an `If-Range` validator when it makes a subsequent
/// request with a `Range` header.  The validator allows the origin server to
/// return a full representation if the stored partial copy is no longer current.
/// Without this check a cache could happily recombine stale fragments and
/// deliver corrupted content.
///
/// This rule looks back over previously recorded transactions for the same
/// client+resource.  When the current request contains a `Range` header and an
/// earlier response in the history was a 206 that included a validator (an
/// entity-tag (ETag) or a Last-Modified date), the rule warns if the present
/// request either omits `If-Range` altogether or supplies a value that does not
/// match the previously observed validator.  Note that strong validation
/// semantics are only guaranteed when using a strong ETag.
///
/// The check is intentionally permissive when the prior 206 response lacked any
/// validators; in that case the cache has nothing it can use in an `If-Range`
/// header and no useful warning can be produced.
pub struct StatefulRangeRequestAndCaching;

impl Rule for StatefulRangeRequestAndCaching {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "stateful_range_request_and_caching"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        config: &Self::Config,
    ) -> Option<Violation> {
        let req = &tx.request;
        let has_range = req.headers.get("range").is_some();
        if !has_range {
            return None;
        }

        // find the most recent 206 Partial Content response in history
        let prev_206 = history.iter().find(|past| {
            if let Some(resp) = &past.response {
                resp.status == 206
            } else {
                false
            }
        });

        let prev_resp = match prev_206 {
            Some(p) => match &p.response {
                Some(r) => r,
                None => return None, // should not happen but be safe
            },
            None => return None,
        };

        // determine if the prior 206 had a validator we could use
        // ignore weak ETags since they cannot be placed in If-Range.
        let (prev_etag, prev_lm) =
            crate::helpers::headers::extract_strong_validators_from_response(&prev_resp.headers);

        // if both are present, the rule will preferentially check the ETag,
        // mirroring how caches themselves pick validators.
        let has_validator = prev_etag.is_some() || prev_lm.is_some();
        if !has_validator {
            // nothing for a cache to validate with (weak ETag alone is ignored)
            return None;
        }

        // current request's If-Range, if any
        let if_range_val = crate::helpers::headers::get_header_str(&req.headers, "if-range");

        if if_range_val.is_none() {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: "Range request made after earlier 206 Partial Content but missing If-Range validator; caches recombining partial responses SHOULD include If-Range to ensure freshness".into(),
            });
        }

        // if we have an If-Range, ensure it matches the previous validator
        if let Some(ifr) = if_range_val {
            let ifr_trimmed = ifr.trim();
            let mut matched = false;
            if let Some(etag_str) = &prev_etag {
                if ifr_trimmed == etag_str.trim() {
                    matched = true;
                }
            }
            if !matched {
                if let Some(lm_str) = &prev_lm {
                    if ifr_trimmed == lm_str.trim() {
                        matched = true;
                    }
                }
            }
            if !matched {
                // Prefer the ETag-specific message when a *strong* ETag was
                // recorded; otherwise fall back to Last-Modified.
                if prev_etag.is_some() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "If-Range value does not match previously observed ETag from a 206 response; cache may recombine with stale partial data".into(),
                    });
                }
                if prev_lm.is_some() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: "If-Range value does not match previously observed Last-Modified from a 206 response; cache may recombine with stale partial data".into(),
                    });
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_prev_with_status_and_headers(
        status: u16,
        headers: &[(&str, &str)],
    ) -> crate::http_transaction::HttpTransaction {
        let mut prev = crate::test_helpers::make_test_transaction_with_response(status, headers);
        prev.request.method = "GET".to_string();
        prev
    }

    #[test]
    fn range_without_if_range_with_no_history_is_ok() {
        let rule = StatefulRangeRequestAndCaching;
        let cfg = crate::test_helpers::make_test_rule_config();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("range", "bytes=0-0")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn range_without_if_range_after_partial_reports() {
        let rule = StatefulRangeRequestAndCaching;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut prev = make_prev_with_status_and_headers(206, &[("etag", "\"a\"")]);
        prev.request.uri = "/r".to_string();
        prev.client = crate::test_helpers::make_test_client();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.uri = "/r".to_string();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("range", "bytes=0-0")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev.clone()]),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("missing If-Range"));
    }

    #[test]
    fn range_with_matching_if_range_is_ok() {
        let rule = StatefulRangeRequestAndCaching;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut prev = make_prev_with_status_and_headers(206, &[("etag", "\"a\"")]);
        prev.request.uri = "/r".to_string();
        prev.client = crate::test_helpers::make_test_client();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.uri = "/r".to_string();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("range", "bytes=0-0"),
            ("if-range", "\"a\""),
        ]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev.clone()]),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn last_modified_validator_matching_if_range_is_ok() {
        let rule = StatefulRangeRequestAndCaching;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut prev = make_prev_with_status_and_headers(
            206,
            &[("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")],
        );
        prev.request.uri = "/r".to_string();
        prev.client = crate::test_helpers::make_test_client();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.uri = "/r".to_string();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("range", "bytes=0-0"),
            ("if-range", "Wed, 21 Oct 2015 07:28:00 GMT"),
        ]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev.clone()]),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn last_modified_validator_mismatch_reports() {
        let rule = StatefulRangeRequestAndCaching;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut prev = make_prev_with_status_and_headers(
            206,
            &[("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")],
        );
        prev.request.uri = "/r".to_string();
        prev.client = crate::test_helpers::make_test_client();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.uri = "/r".to_string();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("range", "bytes=0-0"),
            ("if-range", "Wed, 20 Oct 2015 07:28:00 GMT"),
        ]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev.clone()]),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("does not match"));
    }

    #[test]
    fn range_with_mismatched_if_range_reports() {
        let rule = StatefulRangeRequestAndCaching;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut prev = make_prev_with_status_and_headers(206, &[("etag", "\"a\"")]);
        prev.request.uri = "/r".to_string();
        prev.client = crate::test_helpers::make_test_client();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.uri = "/r".to_string();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("range", "bytes=0-0"),
            ("if-range", "\"b\""),
        ]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev.clone()]),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("does not match"));
    }

    #[test]
    fn partial_without_validator_skips() {
        let rule = StatefulRangeRequestAndCaching;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut prev = make_prev_with_status_and_headers(206, &[]);
        prev.request.uri = "/r".to_string();
        prev.client = crate::test_helpers::make_test_client();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.uri = "/r".to_string();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("range", "bytes=0-0")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev.clone()]),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn previous_not_206_ignored() {
        let rule = StatefulRangeRequestAndCaching;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut prev = make_prev_with_status_and_headers(200, &[("etag", "\"a\"")]);
        prev.request.uri = "/r".to_string();
        prev.client = crate::test_helpers::make_test_client();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.uri = "/r".to_string();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("range", "bytes=0-0")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev.clone()]),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn weak_etag_in_prev_does_not_count_as_validator() {
        let rule = StatefulRangeRequestAndCaching;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut prev = make_prev_with_status_and_headers(206, &[("etag", "W/\"weak\"")]);
        prev.request.uri = "/r".to_string();
        prev.client = crate::test_helpers::make_test_client();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.uri = "/r".to_string();
        tx.client = crate::test_helpers::make_test_client();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("range", "bytes=0-0")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev.clone()]),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "stateful_range_request_and_caching");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn validate_rules_missing_severity_errors() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "stateful_range_request_and_caching",
        ]);
        if let Some(toml::Value::Table(table)) =
            cfg.rules.get_mut("stateful_range_request_and_caching")
        {
            table.remove("severity");
        }

        let res = crate::rules::validate_rules(&cfg);
        assert!(res.is_err());
    }
}
