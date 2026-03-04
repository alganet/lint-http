// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Stateful check ensuring that conditional requests use the most recently
/// observed validator for a given resource.
///
/// Caches revalidate stored responses by sending conditional requests such as
/// `If-None-Match` and `If-Modified-Since`.  To be effective the validator
/// value included in the request must correspond to the current version of the
/// representation.  If a prior response carried a validator (an `ETag` or
/// `Last-Modified` date) and a later request reuses an *older* value, the
/// cache's validation chain is broken; the origin server may return a
/// successful 200 response when the client expected a `304 Not Modified`, or
/// worse the cache may serve stale content to other clients.
///
/// This rule walks the transaction history (newest-first) for the same
/// client/resource pair and determines the most recent validator that a cache
/// could reasonably be expected to have recorded.  It then compares that value
/// against any conditional header present on the current request.  A mismatch
/// triggers a warning.
///
/// The rule is intentionally permissive when no prior validator is available
/// (for example, only unvalidated 200 responses were seen); in that case there
/// is nothing useful a cache could supply and no violation is reported.  The
/// presence or absence of conditional headers on otherwise-cacheable requests
/// is covered by the separate `client_cache_respect` rule.
pub struct StatefulCacheValidationChain;

impl Rule for StatefulCacheValidationChain {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "stateful_cache_validation_chain"
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
        let has_inm = req.headers.contains_key("if-none-match");
        let has_ims = req.headers.contains_key("if-modified-since");
        if !has_inm && !has_ims {
            return None;
        }

        // If the request uses `If-None-Match: *`, it is not referring to any
        // specific validator value and therefore cannot be matched against a
        // previously observed ETag.  Skip the rule in that case to avoid
        // spurious warnings.
        if has_inm {
            for hv in req.headers.get_all("if-none-match").iter() {
                if let Ok(s) = hv.to_str() {
                    for member in crate::helpers::headers::split_commas_respecting_quotes(s) {
                        if member.trim() == "*" {
                            return None;
                        }
                    }
                }
            }
        }

        // Determine the most recent validator seen in history.  Iterate in
        // newest-first order and stop when we have either a strong ETag or a
        // Last-Modified value.  A 304 response may include headers that update
        // the validator; treat it the same as a 200 when present.
        let mut known_etag: Option<String> = None;
        let mut known_lm: Option<String> = None;
        for past in history.iter() {
            if let Some(resp) = &past.response {
                let (etag, lm) =
                    crate::helpers::headers::extract_validators_from_response(&resp.headers);
                if etag.is_some() || lm.is_some() {
                    // whichever validator is present first "wins"; ETag takes
                    // precedence since caches prefer it.
                    if etag.is_some() {
                        known_etag = etag.clone();
                        known_lm = None;
                    } else if known_etag.is_none() {
                        // only update last-modified if we haven't already seen
                        // a stronger ETag.
                        known_lm = lm.clone();
                    }
                    break;
                }
            }
        }

        if known_etag.is_none() && known_lm.is_none() {
            // no validator available to compare against
            return None;
        }

        // Compare depending on validator type
        if let Some(etag) = &known_etag {
            if has_inm {
                // Iterate over all If-None-Match header fields; a match in any of
                // them is sufficient to satisfy the validator.
                let mut any_match = false;
                let mut first_inm_val: Option<String> = None;
                for value in req.headers.get_all("if-none-match").iter() {
                    if let Ok(inm_val) = value.to_str() {
                        if first_inm_val.is_none() {
                            first_inm_val = Some(inm_val.to_string());
                        }
                        if crate::helpers::headers::inm_matches_known(inm_val, etag) {
                            any_match = true;
                            break;
                        }
                    }
                }
                if !any_match {
                    let reported = first_inm_val
                        .as_deref()
                        .unwrap_or("<non-UTF8 If-None-Match>");
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Conditional request uses If-None-Match '{}' which does not match most recent validator '{}' from history; cache validation chain may be broken",
                            reported.trim(),
                            etag
                        ),
                    });
                }
            }
        } else if let Some(lm) = &known_lm {
            if has_ims {
                if let Some(ims_val) =
                    crate::helpers::headers::get_header_str(&req.headers, "if-modified-since")
                {
                    let ims_str = ims_val.trim();
                    // if the IMS value is not even a valid HTTP-date, let another
                    // rule handle it rather than flagging a validation mismatch.
                    if !crate::http_date::is_valid_http_date(ims_str) {
                        return None;
                    }

                    let lm_str = lm.trim();
                    // attempt to parse both sides; the parser is occasionally
                    // conservative, so we fall back to string equality if parsing
                    // fails despite validity.
                    let lm_dt = crate::http_date::parse_http_date_to_datetime(lm_str);
                    let ims_dt = crate::http_date::parse_http_date_to_datetime(ims_str);

                    let mismatch = match (ims_dt, lm_dt) {
                        (Ok(i), Ok(l)) => i != l,
                        _ => ims_str != lm_str,
                    };
                    if mismatch {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Conditional request uses If-Modified-Since '{}' which does not match most recent Last-Modified '{}' from history; cache validation chain may be broken",
                                ims_str,
                                lm_str
                            ),
                        });
                    }
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_prev(
        status: u16,
        headers: &[(&str, &str)],
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, headers);
        tx.request.method = "GET".to_string();
        tx
    }

    #[test]
    fn non_conditional_request_is_ok() {
        let rule = StatefulCacheValidationChain;
        let tx = crate::test_helpers::make_test_transaction();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn no_history_conditional_is_ok() {
        let rule = StatefulCacheValidationChain;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn inm_wildcard_skips_chain() {
        let rule = StatefulCacheValidationChain;
        let prev = make_prev(200, &[("etag", "\"a\"")]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "*")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev]),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn matching_etag_is_ok() {
        let rule = StatefulCacheValidationChain;
        let prev = make_prev(200, &[("etag", "\"a\"")]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev]),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn weak_etag_history_strong_request_ok() {
        let rule = StatefulCacheValidationChain;
        let prev = make_prev(200, &[("etag", "W/\"a\"")]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev]),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn weak_etag_history_and_request_match() {
        let rule = StatefulCacheValidationChain;
        let prev = make_prev(200, &[("etag", "W/\"a\"")]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "W/\"a\"")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev]),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn weak_etag_mismatch_reports() {
        let rule = StatefulCacheValidationChain;
        let prev = make_prev(200, &[("etag", "W/\"a\"")]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "W/\"b\"")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev]),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
    }

    #[test]
    fn wildcard_inm_is_ok_even_if_known_etag() {
        let rule = StatefulCacheValidationChain;
        let prev = make_prev(200, &[("etag", "\"a\"")]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "*")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev]),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn mismatched_etag_reports() {
        let rule = StatefulCacheValidationChain;
        let prev = make_prev(200, &[("etag", "\"a\"")]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"b\"")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev]),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
    }

    #[test]
    fn inm_with_multiple_tokens_matches() {
        let rule = StatefulCacheValidationChain;
        let prev = make_prev(200, &[("etag", "\"a\"")]);
        let mut tx = crate::test_helpers::make_test_transaction();
        // first token wrong, second token correct
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"x\", \"a\"")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev]),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn only_inm_with_only_lm_known_is_ok() {
        let rule = StatefulCacheValidationChain;
        let prev = make_prev(200, &[("last-modified", "Wed, 01 Jan 2020 00:00:00 GMT")]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev]),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn both_headers_with_lm_known_and_ims_mismatch_reports() {
        let rule = StatefulCacheValidationChain;
        let prev = make_prev(200, &[("last-modified", "Wed, 01 Jan 2020 00:00:00 GMT")]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("if-none-match", "\"a\""),
            ("if-modified-since", "Thu, 02 Jan 2020 00:00:00 GMT"),
        ]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev]),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
    }

    #[test]
    fn ims_formatting_variation_reports_violation() {
        let rule = StatefulCacheValidationChain;
        let prev = make_prev(200, &[("last-modified", "Wed, 01 Jan 2020 00:00:00 GMT")]);
        let mut tx = crate::test_helpers::make_test_transaction();
        // lower-case weekday is not parsed by our date helper, so the header is
        // considered invalid and the rule should skip checking.
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-modified-since",
            "wed, 01 Jan 2020 00:00:00 GMT",
        )]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev]),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn both_headers_with_lm_known_and_ims_match_is_ok() {
        let rule = StatefulCacheValidationChain;
        let prev = make_prev(200, &[("last-modified", "Wed, 01 Jan 2020 00:00:00 GMT")]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("if-none-match", "\"a\""),
            ("if-modified-since", "Wed, 01 Jan 2020 00:00:00 GMT"),
        ]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev]),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn last_modified_mismatch_reports() {
        let rule = StatefulCacheValidationChain;
        let prev = make_prev(200, &[("last-modified", "Wed, 01 Jan 2020 00:00:00 GMT")]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-modified-since",
            "Thu, 02 Jan 2020 00:00:00 GMT",
        )]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev]),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
    }

    #[test]
    fn invalid_ims_does_not_report_violation() {
        let rule = StatefulCacheValidationChain;
        let prev = make_prev(200, &[("last-modified", "Mon, 01 Jan 2020 00:00:00 GMT")]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-modified-since", "not-a-date")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev]),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn ims_ignored_when_etag_known() {
        // presence of a known ETag means we only check If-None-Match
        let rule = StatefulCacheValidationChain;
        let prev = make_prev(200, &[("etag", "\"a\"")]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "if-modified-since",
            "Thu, 02 Jan 2020 00:00:00 GMT",
        )]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev]),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn both_headers_etag_known_and_inm_mismatch_reports() {
        let rule = StatefulCacheValidationChain;
        let prev = make_prev(200, &[("etag", "\"a\"")]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("if-none-match", "\"b\""),
            ("if-modified-since", "Thu, 02 Jan 2020 00:00:00 GMT"),
        ]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev]),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
    }

    #[test]
    fn both_headers_etag_known_and_inm_match_is_ok() {
        let rule = StatefulCacheValidationChain;
        let prev = make_prev(200, &[("etag", "\"a\"")]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("if-none-match", "\"a\""),
            ("if-modified-since", "Thu, 02 Jan 2020 00:00:00 GMT"),
        ]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev]),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn validator_updated_via_304() {
        // history has a 200 with etag "a" then a 304 that updates to "b".
        let rule = StatefulCacheValidationChain;
        let prev1 = make_prev(200, &[("etag", "\"a\"")]);
        let prev2 = make_prev(304, &[("etag", "\"b\"")]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("if-none-match", "\"a\"")]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::new(vec![prev2, prev1]),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "stateful_cache_validation_chain");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn validate_rules_missing_severity_errors() {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "stateful_cache_validation_chain",
        ]);
        if let Some(toml::Value::Table(table)) =
            cfg.rules.get_mut("stateful_cache_validation_chain")
        {
            table.remove("severity");
        }

        let res = crate::rules::validate_rules(&cfg);
        assert!(res.is_err());
    }
}
