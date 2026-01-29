// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Detect obvious contradictions or redundant combinations of Cache-Control directives.
/// Examples flagged:
/// - `public` and `private` present simultaneously (contradictory visibility)
/// - `no-store` combined with `public` or `private` (contradiction — no-store forbids storing)
/// - `no-cache` present with `max-age=0` (redundant: both indicate immediate staleness/revalidation)
/// - Multiple `max-age` or `s-maxage` directives with differing values
pub struct MessageCachingDirectiveInteraction;

impl Rule for MessageCachingDirectiveInteraction {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "message_caching_directive_interaction"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        // Helper to check a single HeaderMap for contradictions
        let check_headers = |hdrs: &hyper::HeaderMap| -> Option<Violation> {
            use crate::helpers::headers::split_commas_respecting_quotes;

            // Collect directives across possibly multiple header fields
            let mut directives: Vec<(String, Option<String>)> = Vec::new();

            for hv in hdrs.get_all("cache-control").iter() {
                let s = match hv.to_str() {
                    Ok(s) => s,
                    Err(_) => {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Cache-Control header contains non-UTF8 value".into(),
                        })
                    }
                };

                for member in split_commas_respecting_quotes(s) {
                    let m = member.trim();
                    if m.is_empty() {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: "Cache-Control header contains empty member".into(),
                        });
                    }

                    let mut kv = m.splitn(2, '=');
                    let name = kv.next().unwrap().trim().to_ascii_lowercase();
                    let value = kv.next().map(|v| v.trim().to_string());

                    directives.push((name, value));
                }
            }

            if directives.is_empty() {
                return None;
            }

            use std::collections::HashMap;
            let mut seen: HashMap<String, Vec<Option<String>>> = HashMap::new();
            for (n, v) in directives {
                seen.entry(n).or_default().push(v);
            }

            // public vs private contradiction
            if seen.contains_key("public") && seen.contains_key("private") {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Cache-Control contains both 'public' and 'private' directives (contradictory visibility)".into(),
                });
            }

            // no-store with public/private
            if seen.contains_key("no-store")
                && (seen.contains_key("public") || seen.contains_key("private"))
            {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Cache-Control contains 'no-store' together with 'public' or 'private' (contradiction)".into(),
                });
            }

            // Note: combinations like 'no-cache' with 'max-age=0' are allowed per RFC 9111 §3
            // and are intentionally *not* flagged as redundant by this rule.

            // Multiple max-age or s-maxage conflicting values
            for key in ["max-age", "s-maxage"] {
                if let Some(vals) = seen.get(key) {
                    // Collect numeric values (unquoted token form) and compare
                    let mut nums: Vec<String> = Vec::new();
                    for s in vals.iter().flatten() {
                        let s = s.trim();
                        let inner = if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
                            &s[1..s.len() - 1]
                        } else {
                            s
                        };
                        if !inner.is_empty() {
                            nums.push(inner.to_string());
                        }
                    }
                    if nums.len() > 1 {
                        // if at least two are different, flag
                        let first = &nums[0];
                        if nums.iter().any(|x| x != first) {
                            return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!("Cache-Control contains multiple '{}' directives with differing values", key),
                            });
                        }
                    }
                }
            }

            None
        };

        // Check request and response headers
        if let Some(v) = check_headers(&tx.request.headers) {
            return Some(v);
        }
        if let Some(resp) = &tx.response {
            if let Some(v) = check_headers(&resp.headers) {
                return Some(v);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_req(cc: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("cache-control", cc)]);
        tx
    }

    fn make_resp(cc: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("cache-control", cc)]);
        tx
    }

    #[rstest]
    #[case("public, max-age=3600", false)]
    #[case("public, private", true)]
    #[case("no-store, public", true)]
    #[case("no-cache, max-age=0", false)]
    #[case("no-cache, max-age=60", false)]
    #[case("max-age=60, max-age=60", false)]
    #[case("max-age=60, max-age=30", true)]
    #[case("s-maxage=60, s-maxage=60", false)]
    #[case("s-maxage=60, s-maxage=30", true)]
    fn request_cases(#[case] val: &str, #[case] expect_violation: bool) {
        let rule = MessageCachingDirectiveInteraction;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_req(val);
        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}', got none", val);
        } else {
            assert!(v.is_none(), "unexpected violation for '{}': {:?}", val, v);
        }
    }

    #[rstest]
    #[case("public, max-age=3600", false)]
    #[case("public, private", true)]
    #[case("no-store, public", true)]
    #[case("no-cache, max-age=0", false)]
    #[case("max-age=60, max-age=60", false)]
    #[case("s-maxage=60, s-maxage=30", true)]
    fn response_cases(#[case] val: &str, #[case] expect_violation: bool) {
        let rule = MessageCachingDirectiveInteraction;
        let cfg = crate::test_helpers::make_test_rule_config();
        let tx = make_resp(val);
        let v = rule.check_transaction(&tx, None, &cfg);
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}', got none", val);
        } else {
            assert!(v.is_none(), "unexpected violation for '{}': {:?}", val, v);
        }
    }

    #[test]
    fn non_utf8_header_is_violation() {
        use hyper::header::HeaderValue;
        let mut tx = crate::test_helpers::make_test_transaction();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        let mut hm = hyper::HeaderMap::new();
        hm.insert("cache-control", bad);
        tx.request.headers = hm;
        let rule = MessageCachingDirectiveInteraction;
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn empty_member_is_violation() {
        let rule = MessageCachingDirectiveInteraction;
        let tx = make_req(",max-age=1");
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn quoted_max_age_zero_no_violation() {
        let rule = MessageCachingDirectiveInteraction;
        let tx = make_req("no-cache, max-age=\"0\"");
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn multiple_header_fields_combined_reports_violation() {
        use hyper::header::HeaderValue;
        let rule = MessageCachingDirectiveInteraction;
        let cfg = crate::test_helpers::make_test_rule_config();
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        hm.append("cache-control", HeaderValue::from_static("no-store"));
        hm.append("cache-control", HeaderValue::from_static("public"));
        tx.request.headers = hm;
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn conflicting_max_age_values_reports_violation() {
        let rule = MessageCachingDirectiveInteraction;
        let tx = make_req("max-age=60, max-age=\"30\"");
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_some());
    }

    #[test]
    fn no_cache_control_header_no_violation() {
        let rule = MessageCachingDirectiveInteraction;
        let tx = crate::test_helpers::make_test_transaction();
        let cfg = crate::test_helpers::make_test_rule_config();
        let v = rule.check_transaction(&tx, None, &cfg);
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_caching_directive_interaction");
        let _engine = crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn validate_rules_with_invalid_config_missing_severity() {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_caching_directive_interaction");
        // remove severity to simulate invalid config
        if let Some(toml::Value::Table(ref mut table)) =
            cfg.rules.get_mut("message_caching_directive_interaction")
        {
            table.remove("severity");
        }

        let err = crate::rules::validate_rules(&cfg).expect_err("expected validation to fail");
        assert!(err.to_string().contains("Missing required 'severity'"));
    }
}
