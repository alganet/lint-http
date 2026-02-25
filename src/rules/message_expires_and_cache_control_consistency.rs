// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;
use chrono::{DateTime, Utc};

/// If `Expires` and `Cache-Control` are both present, their values should not contradict.
/// `Cache-Control: max-age` / `s-maxage` override `Expires` (RFC 9111 §5.3); this rule
/// flags clear contradictions (e.g., `max-age=0` with a future Expires, or `max-age>0`
/// while `Expires` is in the past relative to Date).
pub struct MessageExpiresAndCacheControlConsistency;

impl Rule for MessageExpiresAndCacheControlConsistency {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_expires_and_cache_control_consistency"
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
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        // If either header is missing, nothing to check
        let mut has_expires = false;
        let mut expires_dt: Option<DateTime<Utc>> = None;
        if let Some(hv) = resp.headers.get_all("expires").iter().next() {
            if let Ok(s) = hv.to_str() {
                has_expires = true;
                if let Ok(dt) = crate::http_date::parse_http_date_to_datetime(s.trim()) {
                    expires_dt = Some(dt);
                } else {
                    // Let other rules (or server_status_and_caching_semantics) report invalid Expires.
                    return None;
                }
            }
        }

        let mut cc_present = false;
        // Collect Cache-Control response directives of interest
        let mut cc_no_cache = false;
        let mut cc_no_store = false;
        let mut cc_max_age: Option<i64> = None;
        let mut cc_s_maxage: Option<i64> = None;

        for hv in resp.headers.get_all("cache-control").iter() {
            if let Ok(s) = hv.to_str() {
                cc_present = true;
                for part in s.split(',') {
                    let p = part.trim();
                    if p.is_empty() {
                        continue;
                    }
                    let mut it = p.splitn(2, '=');
                    let name = it.next().unwrap().trim().to_ascii_lowercase();
                    match name.as_str() {
                        "no-cache" => cc_no_cache = true,
                        "no-store" => cc_no_store = true,
                        "max-age" => {
                            if let Some(val) = it.next() {
                                if let Ok(n) = val.trim().parse::<i64>() {
                                    cc_max_age = Some(n);
                                }
                            }
                        }
                        "s-maxage" => {
                            if let Some(val) = it.next() {
                                if let Ok(n) = val.trim().parse::<i64>() {
                                    cc_s_maxage = Some(n);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        if !has_expires || !cc_present || expires_dt.is_none() {
            return None;
        }

        let expires = expires_dt.unwrap();

        // Determine reference time: Date header if present, otherwise fall back to the transaction timestamp
        let date_ref = if let Some(hv) = resp.headers.get_all("date").iter().next() {
            if let Ok(s) = hv.to_str() {
                if let Ok(dt) = crate::http_date::parse_http_date_to_datetime(s.trim()) {
                    dt
                } else {
                    tx.timestamp
                }
            } else {
                tx.timestamp
            }
        } else {
            tx.timestamp
        };

        // If no-cache or no-store or max-age=0 but Expires in the future => contradiction
        if (cc_no_cache || cc_no_store || cc_max_age == Some(0)) && expires > date_ref {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Response contains Cache-Control directives {:?} which prevent caching, but Expires indicates freshness until {} — Cache-Control takes precedence (RFC 9111 §5.3)",
                    if cc_no_cache { "no-cache" } else if cc_no_store { "no-store" } else { "max-age=0" },
                    expires
                ),
            });
        }

        // If max-age or s-maxage is positive, but Expires is earlier than Date (already expired) => contradiction
        if (cc_max_age.unwrap_or(-1) > 0 || cc_s_maxage.unwrap_or(-1) > 0) && expires <= date_ref {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Response contains Cache-Control max-age/s-maxage but Expires {} is not in the future relative to Date {} — values are contradictory (RFC 9111 §4.2, §5.3)",
                    expires, date_ref
                ),
            });
        }

        // If max-age exists and Date is present, check that Expires roughly matches Date + max-age (best-effort)
        if resp.headers.contains_key("date") {
            if let Some(max_age) = cc_max_age {
                if max_age >= 0 {
                    let expected = date_ref + chrono::Duration::seconds(max_age);
                    // Allow a small leeway (1 second) for formatting/rounding differences
                    let diff = (expected - expires).num_seconds().abs();
                    if diff > 1 {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Cache-Control max-age={} suggests Expires should be {} (Date + max-age), but Expires is {} — prefer consistent values or omit Expires (RFC 9111 §5.3)",
                                max_age, expected, expires
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
    use crate::test_helpers::{make_test_rule_config, make_test_transaction_with_response};
    use rstest::rstest;

    #[rstest]
    #[case(Some(("cache-control","max-age=3600")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","Wed, 21 Oct 2015 08:28:00 GMT")), false)]
    #[case(Some(("cache-control","max-age=0")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","Wed, 21 Oct 2015 07:29:00 GMT")), true)]
    #[case(Some(("cache-control","no-cache")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","Wed, 21 Oct 2015 08:28:00 GMT")), true)]
    #[case(Some(("cache-control","max-age=60")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","Wed, 21 Oct 2015 07:27:00 GMT")), true)]
    fn expires_and_cache_control_cases(
        #[case] cc: Option<(&str, &str)>,
        #[case] date: Option<(&str, &str)>,
        #[case] expires: Option<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let mut headers = Vec::new();
        if let Some(h) = cc {
            headers.push(h);
        }
        if let Some(d) = date {
            headers.push(d);
        }
        if let Some(e) = expires {
            headers.push(e);
        }

        let tx = make_test_transaction_with_response(200, &headers);
        let rule = MessageExpiresAndCacheControlConsistency;
        let cfg = make_test_rule_config();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for headers={:?}", headers);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation: {:?} for headers={:?}",
                v,
                headers
            );
        }
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_expires_and_cache_control_consistency");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn cache_control_s_maxage_positive_and_expires_in_past_reports_violation() -> anyhow::Result<()>
    {
        let tx = make_test_transaction_with_response(
            200,
            &[
                ("cache-control", "s-maxage=60"),
                ("date", "Wed, 21 Oct 2015 07:28:00 GMT"),
                ("expires", "Wed, 21 Oct 2015 07:27:00 GMT"),
            ],
        );
        let rule = MessageExpiresAndCacheControlConsistency;
        let cfg = make_test_rule_config();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn invalid_expires_is_ignored() -> anyhow::Result<()> {
        let tx = make_test_transaction_with_response(
            200,
            &[("cache-control", "max-age=60"), ("expires", "not-a-date")],
        );
        let rule = MessageExpiresAndCacheControlConsistency;
        let cfg = make_test_rule_config();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        // invalid Expires is left to other rules; this rule returns None
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn max_age_and_expires_within_leeway_is_ok() -> anyhow::Result<()> {
        let tx = make_test_transaction_with_response(
            200,
            &[
                ("cache-control", "max-age=3600"),
                ("date", "Wed, 21 Oct 2015 07:28:00 GMT"),
                ("expires", "Wed, 21 Oct 2015 08:28:01 GMT"),
            ],
        );
        let rule = MessageExpiresAndCacheControlConsistency;
        let cfg = make_test_rule_config();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn non_utf8_cache_control_is_ignored() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let mut tx = make_test_transaction_with_response(200, &[]);
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).unwrap();
        hm.insert("cache-control", bad);
        hm.insert(
            "expires",
            HeaderValue::from_static("Wed, 21 Oct 2015 08:28:00 GMT"),
        );
        tx.response.as_mut().unwrap().headers = hm;
        let rule = MessageExpiresAndCacheControlConsistency;
        let cfg = make_test_rule_config();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        // non-UTF8 cache-control means cc_present stays false -> no violation
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn max_age_malformed_is_ignored_and_no_violation() -> anyhow::Result<()> {
        let tx = make_test_transaction_with_response(
            200,
            &[
                ("cache-control", "max-age=abc"),
                ("date", "Wed, 21 Oct 2015 07:28:00 GMT"),
                ("expires", "Wed, 21 Oct 2015 08:28:00 GMT"),
            ],
        );
        let rule = MessageExpiresAndCacheControlConsistency;
        let cfg = make_test_rule_config();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn missing_date_header_uses_now_and_reports_violation_for_no_cache_future_expires(
    ) -> anyhow::Result<()> {
        use chrono::{TimeZone, Utc};
        // Use a far-future Expires so comparison with Utc::now() is predictable. Build the
        // RFC1123 string using chrono so weekday matches and parsing succeeds.
        let dt = Utc
            .with_ymd_and_hms(2125, 10, 21, 8, 28, 0)
            .single()
            .unwrap();
        let expires = dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let tx = make_test_transaction_with_response(
            200,
            &[("cache-control", "no-cache"), ("expires", &expires)],
        );
        let rule = MessageExpiresAndCacheControlConsistency;
        let cfg = make_test_rule_config();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some(), "got {:?}", v);
        Ok(())
    }

    #[test]
    fn scope_is_message() {
        let rule = MessageExpiresAndCacheControlConsistency;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn parse_far_future_expires_works() -> anyhow::Result<()> {
        use chrono::{Datelike, TimeZone, Utc};
        // Build a valid RFC1123 date far in the future so parsing is predictable
        let dt = Utc
            .with_ymd_and_hms(2125, 10, 21, 8, 28, 0)
            .single()
            .unwrap();
        let s = dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let parsed = crate::http_date::parse_http_date_to_datetime(&s)?;
        assert_eq!(parsed.year(), 2125);
        Ok(())
    }

    #[test]
    fn max_age_and_expires_mismatch_reports_violation() -> anyhow::Result<()> {
        // Date 07:28:00, max-age=3600, Expires 08:27:50 (10 seconds off) => violation
        let tx = make_test_transaction_with_response(
            200,
            &[
                ("cache-control", "max-age=3600"),
                ("date", "Wed, 21 Oct 2015 07:28:00 GMT"),
                ("expires", "Wed, 21 Oct 2015 08:27:50 GMT"),
            ],
        );
        let rule = MessageExpiresAndCacheControlConsistency;
        let cfg = make_test_rule_config();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn no_store_and_future_expires_reports_violation() -> anyhow::Result<()> {
        use chrono::{TimeZone, Utc};
        // Use far future to avoid flakiness
        let dt = Utc
            .with_ymd_and_hms(2125, 10, 21, 8, 28, 0)
            .single()
            .unwrap();
        let expires = dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let tx = make_test_transaction_with_response(
            200,
            &[("cache-control", "no-store"), ("expires", &expires)],
        );
        let rule = MessageExpiresAndCacheControlConsistency;
        let cfg = make_test_rule_config();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn multiple_cache_control_header_fields_combined_reports_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let mut tx = make_test_transaction_with_response(200, &[]);
        let mut hm = HeaderMap::new();
        // two cache-control header fields appended: one is no-cache which should trigger violation
        hm.append("cache-control", HeaderValue::from_static("public"));
        hm.append("cache-control", HeaderValue::from_static("no-cache"));
        use chrono::{TimeZone, Utc};
        let dt = Utc
            .with_ymd_and_hms(2125, 10, 21, 8, 28, 0)
            .single()
            .unwrap();
        let expires_s = dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        hm.insert("expires", HeaderValue::from_str(&expires_s).unwrap());
        tx.response.as_mut().unwrap().headers = hm;
        // Sanity-check the headers we just built; ensure both cache-control header fields are present
        let hm_ref = &tx.response.as_ref().unwrap().headers;
        let cc_vals: Vec<_> = hm_ref
            .get_all("cache-control")
            .iter()
            .map(|hv| hv.to_str().ok().map(|s| s.to_string()))
            .collect();
        assert_eq!(
            cc_vals.len(),
            2,
            "expected two cache-control header fields, got {:?}",
            cc_vals
        );
        // Expires should parse as a valid HTTP date
        assert!(hm_ref
            .get_all("expires")
            .iter()
            .next()
            .and_then(|hv| hv.to_str().ok())
            .is_some());

        // Re-parse Cache-Control here like the rule does and assert we detect `no-cache`
        let mut cc_no_cache = false;
        let mut cc_present = false;
        for hv in hm_ref.get_all("cache-control").iter() {
            if let Ok(s) = hv.to_str() {
                cc_present = true;
                for part in s.split(',') {
                    let p = part.trim();
                    if p.is_empty() {
                        continue;
                    }
                    let mut it = p.splitn(2, '=');
                    let name = it.next().unwrap().trim().to_ascii_lowercase();
                    if name.as_str() == "no-cache" {
                        cc_no_cache = true;
                    }
                }
            }
        }
        assert!(cc_present, "expected cache-control present");
        assert!(
            cc_no_cache,
            "expected to detect no-cache among cache-control values"
        );

        let rule = MessageExpiresAndCacheControlConsistency;
        let cfg = make_test_rule_config();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn non_utf8_expires_is_ignored() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let mut tx = make_test_transaction_with_response(200, &[("cache-control", "max-age=3600")]);
        let mut hm = HeaderMap::new();
        hm.insert("cache-control", HeaderValue::from_static("max-age=3600"));
        let bad = HeaderValue::from_bytes(&[0xff]).unwrap();
        hm.insert("expires", bad);
        tx.response.as_mut().unwrap().headers = hm;
        let rule = MessageExpiresAndCacheControlConsistency;
        let cfg = make_test_rule_config();
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        // non-UTF8 expires means has_expires stays false -> no violation
        assert!(v.is_none());
        Ok(())
    }
}
