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
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
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

        // The second `?` should never fire: `prev_206` was found by matching a 206
        // status, which it could not have done without a response. It stays as a
        // guard rather than an unwrap.
        let prev_resp = prev_206?.response.as_ref()?;

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

    fn description(&self) -> &'static str {
        "Caches that store partial responses (206 Partial Content) risk serving stale or incomplete data if they later satisfy a Range request without validating that those partial fragments still match the current representation.  To avoid this, caches SHOULD supply an `If-Range` validator when issuing a subsequent request that contains a `Range` header; the origin server can then return the entire representation if the stored fragments are out of date (RFC 7233 §3.2).\n\nThis rule tracks earlier transactions for the same client and resource.  If a previous response was 206 and included a **strong** validator (a strong `ETag` – weak tags are ignored – or a `Last-Modified` date), a later Range request is expected to provide `If-Range`.  The rule warns when the header is missing or when its value does not match the validator observed in the earlier 206 response.  Note that while `If-Range` can use either kind of validator, combining partial responses into a complete representation requires a shared strong `ETag` (RFC 9111 §3.4)."
    }

    fn rfc_references(&self) -> &'static [&'static str] {
        &[
            "[RFC 7233 §3.2 — `If-Range` precondition to `Range` requests.](https://www.rfc-editor.org/rfc/rfc7233.html#section-3.2)",
            "[RFC 9111 §4.3.1 — Caches SHOULD send `If-Range` when validating partial responses](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3.1).",
            "[RFC 9111 §3.4 — Combining partial content requires a shared strong validator.](https://www.rfc-editor.org/rfc/rfc9111.html#section-3.4)",
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("— cache includes matching validator"),
                snippet: "GET /resource HTTP/1.1\nRange: bytes=0-99\nIf-Range: \"etag123\"\n\nHTTP/1.1 206 Partial Content\nETag: \"etag123\"\nContent-Range: bytes 0-99/1000",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— validator can be a date"),
                snippet: "GET /resource HTTP/1.1\nRange: bytes=0-99\nIf-Range: Wed, 21 Oct 2015 07:28:00 GMT\n\nHTTP/1.1 206 Partial Content\nLast-Modified: Wed, 21 Oct 2015 07:28:00 GMT\nContent-Range: bytes 0-99/1000",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— missing `If-Range` after earlier 206"),
                snippet: "GET /resource HTTP/1.1\nRange: bytes=0-99\n\nHTTP/1.1 206 Partial Content\nETag: \"etag123\"\nContent-Range: bytes 0-99/1000",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— `If-Range` value does not match previous validator"),
                snippet: "GET /resource HTTP/1.1\nRange: bytes=0-99\nIf-Range: \"other\"\n\nHTTP/1.1 206 Partial Content\nETag: \"etag123\"\nContent-Range: bytes 0-99/1000",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &StatefulRangeRequestAndCaching;

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
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("range", "bytes=0-0")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_range_request_and_caching",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn range_without_if_range_after_partial_reports() {
        let rule = StatefulRangeRequestAndCaching;

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
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev.clone()]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_range_request_and_caching",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("missing If-Range"));
    }

    #[test]
    fn range_with_matching_if_range_is_ok() {
        let rule = StatefulRangeRequestAndCaching;

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
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev.clone()]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_range_request_and_caching",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn last_modified_validator_matching_if_range_is_ok() {
        let rule = StatefulRangeRequestAndCaching;

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
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev.clone()]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_range_request_and_caching",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn last_modified_validator_mismatch_reports() {
        let rule = StatefulRangeRequestAndCaching;

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
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev.clone()]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_range_request_and_caching",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("does not match"));
    }

    #[test]
    fn range_with_mismatched_if_range_reports() {
        let rule = StatefulRangeRequestAndCaching;

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
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev.clone()]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_range_request_and_caching",
            ]),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("does not match"));
    }

    #[test]
    fn partial_without_validator_skips() {
        let rule = StatefulRangeRequestAndCaching;

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
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev.clone()]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_range_request_and_caching",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn previous_not_206_ignored() {
        let rule = StatefulRangeRequestAndCaching;

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
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev.clone()]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_range_request_and_caching",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn weak_etag_in_prev_does_not_count_as_validator() {
        let rule = StatefulRangeRequestAndCaching;

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
            &crate::transaction_history::TransactionHistory::from_transactions(vec![prev.clone()]),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "stateful_range_request_and_caching",
            ]),
        );
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "stateful_range_request_and_caching");
        crate::rules::validate_rules(&cfg)?;
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
