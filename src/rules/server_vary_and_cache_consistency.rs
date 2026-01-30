// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

/// Responses that include `Vary: *` cannot be selected by caches for
/// subsequent requests (a `Vary: *` always fails to match; see RFC 7234 §4.1).
/// If a response also advertises explicit cacheability directives such as
/// `Cache-Control: max-age`/`s-maxage` or `public`, those directives are
/// likely ineffective because caches cannot select stored responses when
/// `Vary: *` is present. This rule flags those cases as likely misconfiguration.
pub struct ServerVaryAndCacheConsistency;

impl Rule for ServerVaryAndCacheConsistency {
    type Config = crate::rules::RuleConfig;

    fn id(&self) -> &'static str {
        "server_vary_and_cache_consistency"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &Self::Config,
    ) -> Option<Violation> {
        let resp = match &tx.response {
            Some(r) => r,
            None => return None,
        };

        // Detect Vary: * across all Vary header fields
        let mut saw_star = false;
        for hv in resp.headers.get_all("vary").iter() {
            let s = match hv.to_str() {
                Ok(s) => s,
                Err(_) => return None, // other rules handle non-utf8 vary values
            };
            for token in crate::helpers::headers::parse_list_header(s) {
                if token == "*" {
                    saw_star = true;
                    break;
                }
            }
            if saw_star {
                break;
            }
        }

        if !saw_star {
            return None;
        }

        // If Vary: * is present, check cache-control directives for explicit cacheability
        for hv in resp.headers.get_all("cache-control").iter() {
            let s = match hv.to_str() {
                Ok(s) => s,
                Err(_) => continue,
            };

            for member in crate::helpers::headers::split_commas_respecting_quotes(s) {
                let m = member.trim();
                if m.is_empty() {
                    continue;
                }
                // directive = token [ '=' ... ]
                let name = m
                    .split('=')
                    .next()
                    .expect("split always yields at least one item")
                    .trim()
                    .to_ascii_lowercase();
                match name.as_str() {
                    "max-age" | "s-maxage" | "public" => {
                        return Some(Violation {
                            rule: self.id().into(),
                            severity: config.severity,
                            message: format!(
                                "Response includes Vary: '*' and Cache-Control directive '{}'; Vary: '*' prevents caches from selecting stored responses, making cache directives like '{}' ineffective (see RFC 7234 §4.1)",
                                name, name
                            ),
                        });
                    }
                    _ => {}
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_tx(vary: Option<&str>, cc: Option<&str>) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = vary {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("vary", v)]);
            if let Some(c) = cc {
                tx.response
                    .as_mut()
                    .unwrap()
                    .headers
                    .append("cache-control", c.parse().unwrap());
            }
        } else if let Some(c) = cc {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("cache-control", c)]);
        }
        tx
    }

    #[rstest]
    #[case(Some("*"), Some("max-age=3600"), true)]
    #[case(Some("*"), Some("s-maxage=3600"), true)]
    #[case(Some("*"), Some("public"), true)]
    #[case(Some("*"), Some("public, max-age=60"), true)]
    #[case(Some("*"), Some("no-cache"), false)]
    #[case(Some("Accept-Encoding"), Some("max-age=60"), false)]
    #[case(None, Some("max-age=60"), false)]
    fn check_cases(
        #[case] vary: Option<&str>,
        #[case] cc: Option<&str>,
        #[case] expect_violation: bool,
    ) {
        let rule = ServerVaryAndCacheConsistency;
        let tx = make_tx(vary, cc);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for vary={:?}, cc={:?}",
                vary,
                cc
            );
        } else {
            assert!(
                v.is_none(),
                "unexpected violation for vary={:?}, cc={:?}: {:?}",
                vary,
                cc,
                v
            );
        }
    }

    #[test]
    fn non_utf8_cache_control_ignored() {
        // non-utf8 cache-control should not panic the rule
        use hyper::header::HeaderValue;
        let rule = ServerVaryAndCacheConsistency;
        let mut tx =
            crate::test_helpers::make_test_transaction_with_response(200, &[("vary", "*")]);
        let bad = HeaderValue::from_bytes(&[0xff]).unwrap();
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .insert("cache-control", bad);
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn id_and_scope_are_expected() {
        let rule = ServerVaryAndCacheConsistency;
        assert_eq!(rule.id(), "server_vary_and_cache_consistency");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn vary_star_across_multiple_header_fields_reports_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = ServerVaryAndCacheConsistency;

        // Vary: Accept-Encoding and Vary: * across header fields, plus Cache-Control: max-age
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.append("vary", HeaderValue::from_static("Accept-Encoding"));
        hm.append("vary", HeaderValue::from_static("*"));
        hm.append("cache-control", HeaderValue::from_static("max-age=60"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
        });

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn cache_control_case_insensitive_directive_detection() {
        let rule = ServerVaryAndCacheConsistency;

        // Public (mixed case) should be detected
        let tx = make_tx(Some("*"), Some("Public"));
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());

        // MAX-AGE uppercase
        let tx2 = make_tx(Some("*"), Some("MAX-AGE=60"));
        let v2 = rule.check_transaction(&tx2, None, &crate::test_helpers::make_test_rule_config());
        assert!(v2.is_some());
    }

    #[test]
    fn multiple_cache_control_headers_with_max_age_reports_violation() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let rule = ServerVaryAndCacheConsistency;

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = HeaderMap::new();
        hm.insert("vary", HeaderValue::from_static("*"));
        hm.append("cache-control", HeaderValue::from_static("no-cache"));
        hm.append("cache-control", HeaderValue::from_static("max-age=60"));
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
        });

        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_some());
    }

    #[test]
    fn extension_directive_only_is_not_a_violation() {
        // Vary: * with a non-cacheability extension should not be flagged
        let rule = ServerVaryAndCacheConsistency;
        let tx = make_tx(Some("*"), Some("foo=bar"));
        let v = rule.check_transaction(&tx, None, &crate::test_helpers::make_test_rule_config());
        assert!(v.is_none());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = ServerVaryAndCacheConsistency;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "server_vary_and_cache_consistency",
        ]);
        // validate_and_box should succeed without error
        let _boxed = rule.validate_and_box(&cfg)?;
        Ok(())
    }
}
