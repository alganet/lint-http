// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Ensures responses that are not cacheable by default include explicit
/// freshness information (e.g., `Cache-Control: max-age=...` / `s-maxage=...` or `Expires`).
/// Default-cacheable status codes are: 200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501.
pub struct ServerStatusAndCachingSemantics;

impl Rule for ServerStatusAndCachingSemantics {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "server_status_and_caching_semantics"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
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

        let status = resp.status;

        // Status codes that are cacheable by default per RFC 9111 §3
        const DEFAULT_CACHEABLE: [u16; 11] =
            [200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501];
        if DEFAULT_CACHEABLE.contains(&status) {
            return None;
        }

        // Helper: check Cache-Control directives for explicit freshness (max-age or s-maxage)
        for hv in resp.headers.get_all("cache-control").iter() {
            if let Ok(s) = hv.to_str() {
                for part in s.split(',') {
                    let p = part.trim();
                    if p.is_empty() {
                        continue;
                    }
                    // split on '=' to check for max-age / s-maxage
                    let mut it = p.splitn(2, '=');
                    let name = it.next().unwrap().trim().to_ascii_lowercase();
                    if name == "max-age" || name == "s-maxage" {
                        if let Some(val) = it.next() {
                            // Accept non-negative integer delta-seconds (allow whitespace)
                            if let Ok(n) = val.trim().parse::<i64>() {
                                if n >= 0 {
                                    return None; // explicit freshness present
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check Expires header for valid HTTP-date
        if let Some(hv) = resp.headers.get_all("expires").iter().next() {
            if let Ok(s) = hv.to_str() {
                if crate::http_date::is_valid_http_date(s.trim()) {
                    return None;
                }
            }
        }

        Some(Violation {
            rule: self.id().into(),
            severity: config.severity,
            message: format!(
                "Response {} is not cacheable by default and lacks explicit freshness information (Cache-Control: max-age/s-maxage or Expires)",
                status
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(302, vec![], true)]
    #[case(302, vec![("cache-control", "max-age=60")], false)]
    #[case(302, vec![("cache-control", "s-maxage=10")], false)]
    #[case(302, vec![("cache-control", "max-age=-1")], true)]
    #[case(302, vec![("cache-control", "max-age=abc")], true)]
    #[case(302, vec![("cache-control", "public"), ("cache-control", "max-age=5")], false)]
    #[case(503, vec![("expires", "Wed, 21 Oct 2015 07:28:00 GMT")], false)]
    #[case(503, vec![("expires", "not-a-date")], true)]
    #[case(200, vec![], false)] // 200 is cacheable by default
    fn caching_cases(
        #[case] status: u16,
        #[case] hdrs: Vec<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = ServerStatusAndCachingSemantics;
        use crate::test_helpers::make_test_transaction_with_response;
        let tx = make_test_transaction_with_response(status, &hdrs);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for status {} headers={:?}",
                status,
                hdrs
            );
        } else {
            assert!(v.is_none(), "unexpected violation: {:?}", v);
        }
        Ok(())
    }

    #[test]
    fn non_utf8_cache_control_is_ignored() -> anyhow::Result<()> {
        let rule = ServerStatusAndCachingSemantics;
        use crate::test_helpers::make_test_transaction_with_response;
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let mut tx = make_test_transaction_with_response(302, &[]);
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).unwrap();
        hm.insert("cache-control", bad);
        tx.response.as_mut().unwrap().headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_rule_config(),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "server_status_and_caching_semantics");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn scope_is_server() {
        let rule = ServerStatusAndCachingSemantics;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }
}
