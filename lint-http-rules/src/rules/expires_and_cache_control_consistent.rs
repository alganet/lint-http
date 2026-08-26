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
pub struct ExpiresAndCacheControlConsistent;

impl Rule for ExpiresAndCacheControlConsistent {
    fn id(&self) -> &'static str {
        "expires_and_cache_control_consistent"
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
        let resp = tx.response.as_ref()?;

        // If either header is missing, nothing to check
        let mut has_expires = false;
        let mut expires_dt: Option<DateTime<Utc>> = None;
        // Expires is an HTTP-date; parse it with the recipient parser (the HTTP-date grammar
        // itself, §5.6.7, is owned by the http_date helper).
        // cite(RFC 9111 § 5.3): "The Expires field value is an HTTP-date timestamp, as defined in Section 5.6.7 of [HTTP]."
        // An unparseable Expires is not missing information: §5.3 assigns it a meaning,
        // so it is retained here (as already-expired) rather than returning early.
        // Reporting the *invalidity* itself still belongs to other rules; what this rule
        // does with it is compare the meaning against Cache-Control.
        let mut expires_raw = String::new();
        if let Some(hv) = resp.headers.get_all("expires").iter().next() {
            if let Ok(s) = hv.to_str() {
                has_expires = true;
                expires_raw = s.trim().to_string();
                if let Ok(dt) = crate::http_date::parse_http_date_to_datetime(s.trim()) {
                    expires_dt = Some(dt);
                }
            }
        }

        let mut cc_present = false;
        // Collect the Cache-Control response directives of interest. `no-cache`/`no-store`
        // and `max-age` are parsed inline here; `s-maxage` uses a shared helper below.
        // (NOTE: `get_cache_control_max_age` exists but is intentionally *not* used — it
        // returns None when no-cache/no-store is also present, whereas the contradiction
        // checks need the raw max-age even then. This divergence is recorded in the tracker.)
        let mut cc_no_cache = false;
        let mut cc_no_store = false;
        let mut cc_max_age: Option<i64> = None;

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
                        _ => {}
                    }
                }
            }
        }
        // Parse s-maxage via a shared helper after the loop so that s-maxage
        // parsing is consistent with other uses in the codebase.
        let cc_s_maxage = crate::helpers::headers::get_cache_control_s_maxage(&resp.headers);

        if !has_expires || !cc_present {
            return None;
        }

        // The recipient is required to read an invalid Expires — `0` above all, the
        // classic anti-caching idiom — as a time already past. So it contradicts a
        // positive max-age/s-maxage exactly the way a stale date does, and the
        // disagreement is sharper than usual: §5.3 says Expires is "only intended for
        // recipients that have not yet implemented the Cache-Control header field", and
        // those are precisely the recipients that will act on the already-expired
        // reading while everyone else honours max-age. Same precedence-not-illegality
        // framing as the dated checks below; needs no reference time, since "already
        // expired" is true against any.
        // cite(RFC 9111 § 5.3): "A cache recipient MUST interpret invalid date formats, especially the value "0", as representing a time in the past (i.e., "already expired")."
        if expires_dt.is_none() {
            if cc_max_age.unwrap_or(-1) > 0 || cc_s_maxage.unwrap_or(-1) > 0 {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "Expires '{}' is not a valid HTTP-date, so a cache MUST read it as already expired, but Cache-Control max-age/s-maxage says the response is still fresh — values are contradictory (RFC 9111 §5.3)",
                        expires_raw
                    ),
                });
            }
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

        // Expires and the Cache-Control freshness directives can disagree. The spec resolves
        // that by *precedence*, not by calling it an error — so flagging the disagreement is
        // this rule's misconfiguration heuristic, built on two facts: for max-age the
        // recipient MUST ignore Expires (§5.3), and the freshness calculation consults max-age
        // before Expires, stopping at the first match (§4.2.1). no-cache/no-store do not
        // "ignore Expires" — their contradiction with a future Expires is a pure heuristic
        // (recorded in the tracker).
        // cite(RFC 9111 § 5.3): "If a response includes a Cache-Control header field with the max-age directive (Section 5.2.2.1), a recipient MUST ignore the Expires header field."
        // cite(RFC 9111 § 4.2.1): "If the max-age response directive (Section 5.2.2.1) is present, use its value, or * If the Expires response header field (Section 5.3) is present, use its value minus the value of the Date response header field"
        if (cc_no_cache || cc_no_store || cc_max_age == Some(0)) && expires > date_ref {
            return Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message: format!(
                    "Response contains Cache-Control directives {:?} that make it non-fresh, but Expires indicates freshness until {} — Cache-Control takes precedence (RFC 9111 §4.2.1)",
                    if cc_no_cache { "no-cache" } else if cc_no_store { "no-store" } else { "max-age=0" },
                    expires
                ),
            });
        }

        // Same misconfiguration heuristic, the other way round: a positive max-age (or, for a
        // shared cache, s-maxage) says "fresh" while Expires is already stale. Per §5.3/§4.2.1
        // the directive wins and Expires is ignored, so this is a consistency flag, not a spec
        // violation — the two values simply disagree.
        // cite(RFC 9111 § 5.3): "If a response includes a Cache-Control header field with the max-age directive (Section 5.2.2.1), a recipient MUST ignore the Expires header field."
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

        // Best-effort consistency: when Date is present, warn if Expires and Date+max-age
        // diverge by more than a second. No requirement makes Expires equal Date+max-age —
        // they are alternatives and max-age wins (§4.2.1/§5.3) — so this is a heuristic with a
        // 1-second formatting/rounding leeway, recorded in the tracker.
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

    fn description(&self) -> &'static str {
        "If a response includes both an `Expires` header and a `Cache-Control` freshness directive\n(such as `max-age`/`s-maxage`) they SHOULD not contradict each other. When both are\npresent, `Cache-Control` directives take precedence; clearly contradictory values\n(e.g., `Cache-Control: no-cache` while `Expires` is in the future) likely indicate\nmisconfiguration and should be corrected.\n\nAn `Expires` value that is not a valid HTTP-date counts as contradictory too, rather\nthan as no information: a cache is required to read it as already expired, so the\ncommon `Expires: 0` paired with a positive `max-age` is flagged."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9111",
                section: Some("5.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-5.3",
                note: "Cache-Control overrides Expires: a recipient MUST ignore Expires when max-age is present, and a shared cache MUST ignore it when s-maxage is present",
            },
            crate::rules::SpecRef {
                spec: "RFC 9111",
                section: Some("4.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2",
                note: "Freshness and age calculations using `max-age`, `s-maxage`, and `Expires`",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nDate: Wed, 21 Oct 2015 07:28:00 GMT\nCache-Control: max-age=3600\nExpires: Wed, 21 Oct 2015 08:28:00 GMT\n\n<...>",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nDate: Wed, 21 Oct 2015 07:28:00 GMT\nCache-Control: max-age=0\nExpires: Wed, 21 Oct 2015 08:28:00 GMT\n\n<...>",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nDate: Wed, 21 Oct 2015 07:28:00 GMT\nCache-Control: no-cache\nExpires: Wed, 21 Oct 2015 08:28:00 GMT\n\n<...>",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ExpiresAndCacheControlConsistent;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_test_transaction_with_response;
    use rstest::rstest;

    #[rstest]
    #[case(Some(("cache-control","max-age=3600")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","Wed, 21 Oct 2015 08:28:00 GMT")), false)]
    #[case(Some(("cache-control","max-age=0")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","Wed, 21 Oct 2015 07:29:00 GMT")), true)]
    #[case(Some(("cache-control","no-cache")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","Wed, 21 Oct 2015 08:28:00 GMT")), true)]
    #[case(Some(("cache-control","max-age=60")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","Wed, 21 Oct 2015 07:27:00 GMT")), true)]
    // An invalid Expires means "already expired", so it contradicts a positive
    // max-age/s-maxage just as a past date does — `0` is the classic idiom.
    #[case(Some(("cache-control","max-age=3600")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","0")), true)]
    #[case(Some(("cache-control","s-maxage=3600")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","not-a-date")), true)]
    // ... but agrees with directives that already deny reuse, so those stay quiet.
    #[case(Some(("cache-control","no-store")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","0")), false)]
    #[case(Some(("cache-control","max-age=0")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","0")), false)]
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
        let rule = ExpiresAndCacheControlConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "expires_and_cache_control_consistent",
        ]);
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
        crate::test_helpers::enable_rule(&mut cfg, "expires_and_cache_control_consistent");
        crate::rules::validate_rules(&cfg)?;
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
        let rule = ExpiresAndCacheControlConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "expires_and_cache_control_consistent",
        ]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn invalid_expires_reads_as_already_expired_and_contradicts_max_age() -> anyhow::Result<()> {
        let tx = make_test_transaction_with_response(
            200,
            &[("cache-control", "max-age=60"), ("expires", "not-a-date")],
        );
        let rule = ExpiresAndCacheControlConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "expires_and_cache_control_consistent",
        ]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        // Reporting the invalidity itself is another rule's job, but its *meaning*
        // is fixed by §5.3 — already expired — which max-age=60 contradicts.
        let v = v.expect("expected a contradiction violation");
        assert!(v.message.contains("already expired"));
        assert!(v.message.contains("not-a-date"));
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
        let rule = ExpiresAndCacheControlConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "expires_and_cache_control_consistent",
        ]);
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
        let rule = ExpiresAndCacheControlConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "expires_and_cache_control_consistent",
        ]);
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
        let rule = ExpiresAndCacheControlConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "expires_and_cache_control_consistent",
        ]);
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
        let rule = ExpiresAndCacheControlConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "expires_and_cache_control_consistent",
        ]);
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
        let rule = ExpiresAndCacheControlConsistent;
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
        let rule = ExpiresAndCacheControlConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "expires_and_cache_control_consistent",
        ]);
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
        let rule = ExpiresAndCacheControlConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "expires_and_cache_control_consistent",
        ]);
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

        let rule = ExpiresAndCacheControlConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "expires_and_cache_control_consistent",
        ]);
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
        let rule = ExpiresAndCacheControlConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "expires_and_cache_control_consistent",
        ]);
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
