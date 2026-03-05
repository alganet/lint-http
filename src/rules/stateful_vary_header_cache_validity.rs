// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Stateful check ensuring that caches (and caching clients) treat `Vary`
/// dimensions as part of their cache key.
///
/// When a response includes a `Vary` header, a cache MUST only match a stored
/// representation for a new request if the values of *all* listed request
/// headers are identical to the values that produced the stored response
/// (see RFC 9111 §4.1).  A client that reuses a cached entry by issuing a
/// conditional request (If-None-Match / If-Modified-Since) should therefore
/// preserve the same set of header values; otherwise the cache key is
/// incomplete and the server may be asked to validate the wrong representation.
///
/// This rule examines conditional requests and attempts to locate the prior
/// transaction whose validator (ETag or Last-Modified) is being reused.  If
/// that earlier response carried a `Vary` header, the rule compares the values
/// of the listed request fields between the two requests.  Any mismatch
/// triggers a warning, because it suggests the cache key omitted one of the
/// necessary dimensions.
///
/// The rule is permissive in several respects:
///
/// * If no previous response matching the current validator is found,
///   nothing useful can be checked.
/// * `Vary: *` is ignored since it prevents reuse altogether and offers no
///   concrete fields to compare.
/// * Weak ETags are treated the same as strong tags for the purpose of
///   locating a prior transaction; the rule does not attempt to revalidate
///   semantics.
pub struct StatefulVaryHeaderCacheValidity;

impl Rule for StatefulVaryHeaderCacheValidity {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "stateful_vary_header_cache_validity"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // rule inspects both request and response history
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
            // nothing to check when client is not reusing a cached validator
            return None;
        }

        // early exit for wildcard INM
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

        // find the prior transaction that supplied the validator
        let mut matched_past: Option<&crate::http_transaction::HttpTransaction> = None;
        let mut matched_validator: Option<String> = None;

        for past in history.iter() {
            if let Some(resp) = &past.response {
                // check ETag first
                if has_inm {
                    if let Some(etag) = resp.headers.get("etag").and_then(|hv| hv.to_str().ok()) {
                        // Does current request present an If-None-Match that
                        // matches this etag?
                        for inm_val in req.headers.get_all("if-none-match").iter() {
                            if let Ok(inm_str) = inm_val.to_str() {
                                if crate::helpers::headers::inm_matches_known(inm_str, etag) {
                                    matched_past = Some(past);
                                    matched_validator = Some(etag.trim().to_string());
                                    break;
                                }
                            }
                        }
                        if matched_past.is_some() {
                            break;
                        }
                    }
                }
                // if we haven't matched yet and we have IMS, try that
                if matched_past.is_none() && has_ims {
                    if let Some(lm) = resp
                        .headers
                        .get("last-modified")
                        .and_then(|hv| hv.to_str().ok())
                    {
                        let lm_trimmed = lm.trim();
                        for ims_hdr in req.headers.get_all("if-modified-since").iter() {
                            if let Ok(ims_val) = ims_hdr.to_str() {
                                let ims_str = ims_val.trim();
                                // only compare if both look like valid HTTP dates
                                if crate::http_date::is_valid_http_date(ims_str) {
                                    // simple string equality is acceptable here; the
                                    // canonicalization rules are handled in other
                                    // rules and our goal is just to locate the
                                    // matching transaction.
                                    if ims_str == lm_trimmed {
                                        matched_past = Some(past);
                                        matched_validator = Some(lm_trimmed.to_string());
                                        break;
                                    }
                                }
                            }
                        }
                        if matched_past.is_some() {
                            break;
                        }
                    }
                }
            }
        }

        let past = matched_past?; // no validator candidate found

        // collect Vary header fields from that past response
        let mut vary_fields: Vec<String> = Vec::new();
        for hv in past
            .response
            .as_ref()
            .unwrap()
            .headers
            .get_all("vary")
            .iter()
        {
            if let Ok(s) = hv.to_str() {
                for tok in crate::helpers::headers::parse_list_header(s) {
                    let t = tok.trim();
                    if t == "*" {
                        // wildcard; nothing to compare
                        return None;
                    }
                    if !t.is_empty() {
                        vary_fields.push(t.to_ascii_lowercase());
                    }
                }
            } else {
                // ignore non-UTF8 Vary values; other rules will handle
                return None;
            }
        }

        if vary_fields.is_empty() {
            return None;
        }

        for field in vary_fields {
            let past_val =
                crate::helpers::headers::get_all_header_values(&past.request.headers, &field)
                    .unwrap_or_default();
            let curr_val = crate::helpers::headers::get_all_header_values(&req.headers, &field)
                .unwrap_or_default();
            if past_val != curr_val {
                let reported_validator = matched_validator.as_deref().unwrap_or("<unknown>");
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "Conditional request with validator '{}' differs in Vary field '{}'; cache key must incorporate all Vary dimensions",
                        reported_validator, field
                    ),
                });
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tx_with_req(uri: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.uri = uri.to_string();
        tx
    }

    fn make_resp_tx(
        req_uri: &str,
        vary: Option<&str>,
        validator: Option<&str>,
    ) -> crate::http_transaction::HttpTransaction {
        let mut tx = make_tx_with_req(req_uri);
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        if let Some(v) = vary {
            headers.append("vary", v.parse().unwrap());
        }
        if let Some(val) = validator {
            // choose header based on prefix
            if val.starts_with('"') || val.starts_with("W/") {
                headers.append("etag", val.parse().unwrap());
            } else {
                headers.append("last-modified", val.parse().unwrap());
            }
        }
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers,
            body_length: None,
        });
        tx
    }

    #[test]
    fn no_violation_without_conditional() {
        let rule = StatefulVaryHeaderCacheValidity;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_tx_with_req("https://example.com/foo");
        let history = crate::transaction_history::TransactionHistory::empty();
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn inm_wildcard_skips() {
        let rule = StatefulVaryHeaderCacheValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut past = make_resp_tx(
            "https://example.com/foo",
            Some("Accept-Encoding"),
            Some("\"etag1\""),
        );
        past.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("Accept-Encoding", "gzip")]);

        let mut tx = make_tx_with_req("https://example.com/foo");
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("If-None-Match", "*"),
            ("Accept-Encoding", "deflate"),
        ]);

        let history = crate::transaction_history::TransactionHistory::new(vec![past]);
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn mismatch_on_vary_field_triggers() {
        let rule = StatefulVaryHeaderCacheValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        // past response had Vary: Accept-Encoding, and request used gzip
        let mut past = make_resp_tx(
            "https://example.com/foo",
            Some("Accept-Encoding"),
            Some("\"etag1\""),
        );
        past.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("Accept-Encoding", "gzip")]);

        // current request uses conditional with same ETag but different
        // Accept-Encoding value
        let mut tx = make_tx_with_req("https://example.com/foo");
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("If-None-Match", "\"etag1\""),
            ("Accept-Encoding", "deflate"),
        ]);

        let history = crate::transaction_history::TransactionHistory::new(vec![past]);
        let v = rule.check_transaction(&tx, &history, &cfg);
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .to_lowercase()
            .contains("accept-encoding"));
    }

    #[test]
    fn match_on_vary_field_ok() {
        let rule = StatefulVaryHeaderCacheValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut past = make_resp_tx(
            "https://example.com/foo",
            Some("Accept-Encoding"),
            Some("\"etag1\""),
        );
        past.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("Accept-Encoding", "gzip")]);

        let mut tx = make_tx_with_req("https://example.com/foo");
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("If-None-Match", "\"etag1\""),
            ("Accept-Encoding", "gzip"),
        ]);

        let history = crate::transaction_history::TransactionHistory::new(vec![past]);
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn missing_vary_header_in_past_skips() {
        let rule = StatefulVaryHeaderCacheValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut past = make_resp_tx("https://example.com/foo", None, Some("\"etag1\""));
        past.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("Accept-Encoding", "gzip")]);

        let mut tx = make_tx_with_req("https://example.com/foo");
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("If-None-Match", "\"etag1\""),
            ("Accept-Encoding", "deflate"),
        ]);

        let history = crate::transaction_history::TransactionHistory::new(vec![past]);
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn vary_wildcard_ignored() {
        let rule = StatefulVaryHeaderCacheValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut past = make_resp_tx("https://example.com/foo", Some("*"), Some("\"etag1\""));
        past.request.headers = crate::test_helpers::make_headers_from_pairs(&[]);

        let mut tx = make_tx_with_req("https://example.com/foo");
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("If-None-Match", "\"etag1\""),
            ("Accept-Encoding", "gzip"),
        ]);

        let history = crate::transaction_history::TransactionHistory::new(vec![past]);
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn case_insensitive_vary_name() {
        let rule = StatefulVaryHeaderCacheValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut past = make_resp_tx(
            "https://example.com/foo",
            Some("aCcEpT-enCoDiNg"),
            Some("\"etag1\""),
        );
        past.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("accept-encoding", "gzip")]);

        let mut tx = make_tx_with_req("https://example.com/foo");
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("If-None-Match", "\"etag1\""),
            ("Accept-Encoding", "deflate"),
        ]);

        let history = crate::transaction_history::TransactionHistory::new(vec![past]);
        let v = rule.check_transaction(&tx, &history, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("accept-encoding"));
    }

    #[test]
    fn missing_current_header_is_mismatch() {
        let rule = StatefulVaryHeaderCacheValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut past = make_resp_tx(
            "https://example.com/foo",
            Some("Accept-Encoding"),
            Some("\"etag1\""),
        );
        past.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("Accept-Encoding", "gzip")]);

        let mut tx = make_tx_with_req("https://example.com/foo");
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("If-None-Match", "\"etag1\""),
            // no Accept-Encoding header
        ]);

        let history = crate::transaction_history::TransactionHistory::new(vec![past]);
        let v = rule.check_transaction(&tx, &history, &cfg);
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .to_lowercase()
            .contains("accept-encoding"));
    }

    #[test]
    fn multiple_vary_fields_one_mismatch_reports() {
        let rule = StatefulVaryHeaderCacheValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut past = make_resp_tx(
            "https://example.com/foo",
            Some("Accept-Encoding, X-Foo"),
            Some("\"etag1\""),
        );
        past.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("Accept-Encoding", "gzip"),
            ("X-Foo", "bar"),
        ]);

        let mut tx = make_tx_with_req("https://example.com/foo");
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("If-None-Match", "\"etag1\""),
            ("Accept-Encoding", "gzip"),
            ("X-Foo", "baz"),
        ]);

        let history = crate::transaction_history::TransactionHistory::new(vec![past]);
        let v = rule.check_transaction(&tx, &history, &cfg);
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("x-foo"));
    }

    #[test]
    fn ims_based_validation_respects_vary() {
        let rule = StatefulVaryHeaderCacheValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut past = make_resp_tx(
            "https://example.com/foo",
            Some("X-Foo"),
            Some("Wed, 21 Oct 2015 07:28:00 GMT"),
        );
        past.request.headers = crate::test_helpers::make_headers_from_pairs(&[("X-Foo", "a")]);

        let mut tx = make_tx_with_req("https://example.com/foo");
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("If-Modified-Since", "Wed, 21 Oct 2015 07:28:00 GMT"),
            ("X-Foo", "b"),
        ]);

        let history = crate::transaction_history::TransactionHistory::new(vec![past]);
        let v = rule.check_transaction(&tx, &history, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn different_validator_skips() {
        let rule = StatefulVaryHeaderCacheValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut past = make_resp_tx(
            "https://example.com/foo",
            Some("Accept-Encoding"),
            Some("\"etag1\""),
        );
        past.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("Accept-Encoding", "gzip")]);

        let mut tx = make_tx_with_req("https://example.com/foo");
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("If-None-Match", "\"etag2\""),
            ("Accept-Encoding", "deflate"),
        ]);

        let history = crate::transaction_history::TransactionHistory::new(vec![past]);
        assert!(rule.check_transaction(&tx, &history, &cfg).is_none());
    }

    #[test]
    fn weak_etag_matches_and_respects_vary() {
        let rule = StatefulVaryHeaderCacheValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        let mut past = make_resp_tx(
            "https://example.com/foo",
            Some("Accept-Encoding"),
            Some("W/\"weak\""),
        );
        past.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("Accept-Encoding", "gzip")]);

        let mut tx = make_tx_with_req("https://example.com/foo");
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("If-None-Match", "W/\"weak\""),
            ("Accept-Encoding", "deflate"),
        ]);

        let history = crate::transaction_history::TransactionHistory::new(vec![past]);
        let v = rule.check_transaction(&tx, &history, &cfg);
        assert!(v.is_some());
        assert!(v
            .unwrap()
            .message
            .to_lowercase()
            .contains("accept-encoding"));
    }

    #[test]
    fn finds_match_in_later_history_entry() {
        let rule = StatefulVaryHeaderCacheValidity;
        let cfg = crate::test_helpers::make_test_rule_config();

        // first past entry has a different etag
        let mut old = make_resp_tx(
            "https://example.com/foo",
            Some("Accept-Encoding"),
            Some("\"old\""),
        );
        old.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("Accept-Encoding", "gzip")]);

        // second entry matches validator but has Vary header
        let mut good = make_resp_tx(
            "https://example.com/foo",
            Some("Accept-Encoding"),
            Some("\"etag1\""),
        );
        good.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("Accept-Encoding", "gzip")]);

        let mut tx = make_tx_with_req("https://example.com/foo");
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[
            ("If-None-Match", "\"etag1\""),
            ("Accept-Encoding", "deflate"),
        ]);

        // newest-first: later matching entry (good) must come first
        let history = crate::transaction_history::TransactionHistory::new(vec![good, old]);
        let v = rule.check_transaction(&tx, &history, &cfg);
        assert!(v.is_some(), "should inspect later matching entry");
    }

    #[test]
    fn validate_rules_with_valid_config() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "stateful_vary_header_cache_validity");
        let _engine = crate::rules::validate_rules(&cfg).unwrap();
    }
}
